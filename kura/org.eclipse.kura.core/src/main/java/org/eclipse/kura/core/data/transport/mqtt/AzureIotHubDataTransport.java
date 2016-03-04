package org.eclipse.kura.core.data.transport.mqtt;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.SSLSocketFactory;

import org.eclipse.kura.KuraConnectException;
import org.eclipse.kura.KuraException;
import org.eclipse.kura.KuraNotConnectedException;
import org.eclipse.kura.KuraTimeoutException;
import org.eclipse.kura.KuraTooManyInflightMessagesException;
import org.eclipse.kura.configuration.ConfigurableComponent;
import org.eclipse.kura.core.data.transport.mqtt.MqttClientConfiguration.PersistenceType;
import org.eclipse.kura.core.util.ValidationUtil;
import org.eclipse.kura.crypto.CryptoService;
import org.eclipse.kura.data.DataTransportListener;
import org.eclipse.kura.data.DataTransportService;
import org.eclipse.kura.data.DataTransportToken;
import org.eclipse.kura.ssl.SslManagerService;
import org.eclipse.kura.ssl.SslServiceListener;
import org.eclipse.kura.status.CloudConnectionStatusComponent;
import org.eclipse.kura.status.CloudConnectionStatusEnum;
import org.eclipse.kura.status.CloudConnectionStatusService;
import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.IMqttToken;
import org.eclipse.paho.client.mqttv3.MqttAsyncClient;
import org.eclipse.paho.client.mqttv3.MqttCallback;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.MqttPersistenceException;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;
import org.osgi.service.component.ComponentContext;
import org.osgi.util.tracker.ServiceTracker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.microsoft.azure.iothub.auth.IotHubSasToken;

public class AzureIotHubDataTransport implements DataTransportService, MqttCallback, ConfigurableComponent, SslServiceListener, CloudConnectionStatusComponent{

	private static final Logger s_logger = LoggerFactory.getLogger(AzureIotHubDataTransport.class);
	private static final Object IOTHUB_DEVICE_CONNECTION_STRING_PROP_NAME = "connection.string";
	private static final String MQTT_KEEP_ALIVE_PROP_NAME = "keep.alive";

	private static final String HOSTNAME_ATTRIBUTE = "HostName=";
	private static final String DEVICE_ID_ATTRIBUTE = "DeviceId=";
	private static final String SHARED_ACCESS_KEY_ATTRIBUTE = "SharedAccessKey=";
	private static final int PORT = 8883;

	private static final String MQTT_BROKER_URL_PROP_NAME = "broker-url";
	private static final String MQTT_USERNAME_PROP_NAME = "username";
	private static final String MQTT_PASSWORD_PROP_NAME = "password";
	private static final String MQTT_CLIENT_ID_PROP_NAME = "client-id";
	private static final String SSL_SCHEME = "ssl://";

	private Map<String, Object> m_properties = new HashMap<String, Object>();

	private SslManagerService m_sslManagerService;
	private CryptoService m_cryptoService;
	private CloudConnectionStatusService m_cloudConnectionStatusService;

	private CloudConnectionStatusEnum m_notificationStatus = CloudConnectionStatusEnum.OFF;

	private MqttClientConfiguration m_clientConf;
	private MqttAsyncClient m_mqttClient;
	private DataTransportListeners m_dataTransportListeners;

	private String m_connectionString = "";
	private String m_sessionId;
	private boolean m_newSession;

	public void setSslManagerService(SslManagerService sslManagerService) {
		this.m_sslManagerService = sslManagerService;
	}

	public void unsetSslManagerService(SslManagerService sslManagerService) {
		this.m_sslManagerService = null;
	}

	public void setCryptoService(CryptoService cryptoService) {
		this.m_cryptoService = cryptoService;
	}

	public void unsetCryptoService(CryptoService cryptoService) {
		this.m_cryptoService = null;
	}

	public void setCloudConnectionStatusService(CloudConnectionStatusService cloudConnectionStatusService) {
		this.m_cloudConnectionStatusService = cloudConnectionStatusService;
	}

	public void unsetCloudConnectionStatusService(CloudConnectionStatusService cloudConnectionStatusService) {
		this.m_cloudConnectionStatusService = null;
	}

	//==============================================================================
	// Activation APIs
	//==============================================================================
	protected void activate(ComponentContext componentContext, Map<String, Object> properties) {
		s_logger.info("Activating...");

		//Set up properties
		for(Map.Entry<String, Object> entry : properties.entrySet()) {
			String key = entry.getKey();
			Object value = entry.getValue();
			if(key.equals(IOTHUB_DEVICE_CONNECTION_STRING_PROP_NAME)) {
				String connectionString = (String)value;
				try{
					char[] decryptedConnectionString = m_cryptoService.decryptAes(((String) value).toCharArray());
					connectionString = String.valueOf(decryptedConnectionString);
				} catch (Exception e) {
					s_logger.info("Password is not encrypted");
				}
				loadDataFromConnectionString(connectionString);
			} else {
				m_properties .put(key, value);
			}
		}

		ServiceTracker<DataTransportListener, DataTransportListener> listenersTracker = new ServiceTracker<DataTransportListener, DataTransportListener>(
				componentContext.getBundleContext(), DataTransportListener.class, null);

		m_dataTransportListeners = new DataTransportListeners(listenersTracker);
		
		//Build configuration and setup MQTT Connection
		try{
			m_clientConf = buildConfiguration(m_properties);
			setupMqttSession();
			m_dataTransportListeners.onConfigurationUpdated(false);
			//this.connect();
		} catch (RuntimeException e){
			s_logger.error("Invalid client configuration. Service will not be able to connect until the configuration is updated", e);
		}

		s_logger.info("Done.");
	}

	protected void deactivate(ComponentContext componentContext) {
		s_logger.info("Deactivating...");

		if(isConnected()){
			disconnect(0);
		}

		m_dataTransportListeners.close();
	}

	protected void updated(Map<String, Object> properties) {
		s_logger.info("Updating...");

		for(Map.Entry<String, Object> entry : properties.entrySet()) {
			String key = entry.getKey();
			Object value = entry.getValue();
			if(key.equals(IOTHUB_DEVICE_CONNECTION_STRING_PROP_NAME)) {
				String connectionString = (String)value;
				try{
					char[] decryptedConnectionString = m_cryptoService.decryptAes(((String) value).toCharArray());
					connectionString = String.valueOf(decryptedConnectionString);
				} catch (Exception e) {
					s_logger.info("Password is not encrypted");
				}
				loadDataFromConnectionString(connectionString);
			} else {
				m_properties .put(key, value);
			}
		}

		update();
	}

	//==============================================================================
	// Paho APIs
	//==============================================================================
	@Override
	public void connectionLost(Throwable t) {
		s_logger.warn("Connection Lost", t);
		m_dataTransportListeners.onConnectionLost(t);
	}

	@Override
	public void deliveryComplete(IMqttDeliveryToken token) {
		if(token != null){
			MqttMessage msg = null;
			try{
				msg = token.getMessage();
			} catch (MqttException e){
				s_logger.error("Cannot get message", e);
				return;
			}

			if(msg != null){
				int qos = msg.getQos();

				if(qos == 0){
					s_logger.debug("Ignoring deliveryComplete for messages published with QoS == 0");
					return;
				}
			}

			int id = token.getMessageId();

			s_logger.debug("Delivery complete for message with ID: {}", id);

			DataTransportToken dataPublisherToken = new DataTransportToken(id, m_sessionId);
			m_dataTransportListeners.onMessageConfirmed(dataPublisherToken);
		} else {
			s_logger.error("Null token.");
		}
	}

	@Override
	public void messageArrived(String topic, MqttMessage message) throws Exception {
		s_logger.debug("Message arrived on topic: {}", topic);

		m_dataTransportListeners.onMessageArrived(topic, message.getPayload(), message.getQos(), message.isRetained());
	}

	//==============================================================================
	// DataTransportService APIs
	//==============================================================================

	@Override
	public synchronized void connect() throws KuraConnectException {
		if(isConnected()){
			s_logger.error("Already connected.");
			throw new IllegalStateException("Already connected.");
		}

		//Setup the MQTT Session
		setupMqttSession();

		if(m_mqttClient == null){
			s_logger.error("Invalid configuration.");
			throw new IllegalStateException("Invalid configuration.");
		}

		s_logger.info("# ------------------------------------------------------------");
		s_logger.info("#  Connection Properties");
		s_logger.info("#  broker          = " + m_clientConf.getBrokerUrl());
		s_logger.info("#  clientId        = " + m_clientConf.getClientId());
		s_logger.info("#  username        = " + m_clientConf.getConnectOptions().getUserName());
		s_logger.info("#  password        = XXXXXXXXXXXXXX");
		s_logger.info("#  keepAlive       = " + m_clientConf.getConnectOptions().getKeepAliveInterval());
		s_logger.info("#  timeout         = " + m_clientConf.getConnectOptions().getConnectionTimeout());
		s_logger.info("#  cleanSession    = " + m_clientConf.getConnectOptions().isCleanSession());
		s_logger.info("#  MQTT version    = 4");
		s_logger.info("#  willDestination = " + m_clientConf.getConnectOptions().getWillDestination());
		s_logger.info("#  willMessage     = " + m_clientConf.getConnectOptions().getWillMessage());
		s_logger.info("#");
		s_logger.info("#  Connecting...");

		//Register the component in the CloudConnectionStatus service
		m_cloudConnectionStatusService.register(this);
		//Update status notification service
		m_cloudConnectionStatusService.updateStatus(this, CloudConnectionStatusEnum.FAST_BLINKING);

		//Connect
		try {
			IMqttToken connectToken = m_mqttClient.connect(m_clientConf.getConnectOptions());
			connectToken.waitForCompletion(10000);
			s_logger.info("#  Connected!");
			s_logger.info("# ------------------------------------------------------------");

			//Update status notification service
			m_cloudConnectionStatusService.updateStatus(this, CloudConnectionStatusEnum.ON);
		} catch (MqttException e1) {
			s_logger.warn("xxx Connect failed. Forcing disconnect. xxx {}", e1);
			try{
				m_mqttClient.setCallback(null);
				m_mqttClient.close();
			} catch (Exception e2){
				s_logger.warn("Forced disconnect exception.", e2);
			} finally {
				m_mqttClient = null;
			}

			//Update status notification service
			m_cloudConnectionStatusService.updateStatus(this, CloudConnectionStatusEnum.OFF);

			throw new KuraConnectException(e1, "Cannot connect");
		} finally {
			m_cloudConnectionStatusService.unregister(this);
		}

		//Notify the listeners
		m_dataTransportListeners.onConnectionEstablished(m_newSession);
	}

	@Override
	public boolean isConnected() {
		if(m_mqttClient != null){
			return m_mqttClient.isConnected();
		}
		return false;
	}

	@Override
	public String getBrokerUrl() {
		if(m_clientConf != null){
			return m_clientConf.getBrokerUrl();
		}
		return "";
	}

	@Override
	public String getAccountName() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getUsername() {
		if(m_clientConf != null){
			return m_clientConf.getConnectOptions().getUserName();
		}
		return "";
	}

	@Override
	public String getClientId() {
		if(m_clientConf != null){
			return m_clientConf.getClientId();
		}
		return "";
	}

	@Override
	public void disconnect(long quiesceTimeout) {
		if(isConnected()){
			s_logger.info("Disconnecting...");

			m_dataTransportListeners.onDisconnecting();

			try{
				IMqttToken token = m_mqttClient.disconnect(quiesceTimeout);
				token.waitForCompletion(10000);
				s_logger.info("Disconnected");
			} catch(MqttException e){
				s_logger.error("Disconnect failed", e);
			}

			m_dataTransportListeners.onDisconnected();
		} else {
			s_logger.warn("MQTT client already disconnected");
		}
	}

	@Override
	public void subscribe(String topic, int qos) throws KuraTimeoutException, KuraException, KuraNotConnectedException {
		if (m_mqttClient == null || !m_mqttClient.isConnected()) {
			throw new KuraNotConnectedException("Not connected");
		}

		s_logger.info("Subscribing to topic: {} with QoS: {}", topic, qos);

		try {
			IMqttToken token = m_mqttClient.subscribe(topic, qos);
			token.waitForCompletion(10000);
		} catch (MqttException e) {
			if (e.getReasonCode() == MqttException.REASON_CODE_CLIENT_TIMEOUT) {
				s_logger.warn("Timeout subscribing to topic: {}", topic);
				throw new KuraTimeoutException("Timeout subscribing to topic: " + topic, e);
			} else {
				s_logger.error("Cannot subscribe to topic: " + topic, e);
				throw KuraException.internalError(e, "Cannot subscribe to topic: " + topic);
			}
		}
	}

	@Override
	public void unsubscribe(String topic) throws KuraTimeoutException, KuraException, KuraNotConnectedException {
		if (m_mqttClient == null || !m_mqttClient.isConnected()) {
			throw new KuraNotConnectedException("Not connected");
		}

		s_logger.info("Unsubscribing to topic: {}", topic);

		try {
			IMqttToken token = m_mqttClient.unsubscribe(topic);
			token.waitForCompletion(10000);
		} catch (MqttException e) {
			if (e.getReasonCode() == MqttException.REASON_CODE_CLIENT_TIMEOUT) {
				s_logger.warn("Timeout unsubscribing to topic: {}", topic);
				throw new KuraTimeoutException("Timeout unsubscribing to topic: " + topic, e);
			} else {
				s_logger.error("Cannot unsubscribe to topic: " + topic, e);
				throw KuraException.internalError(e, "Cannot unsubscribe to topic: " + topic);
			}
		}
	}

	@Override
	public DataTransportToken publish(String topic, byte[] payload, int qos, boolean retain)
			throws KuraTooManyInflightMessagesException, KuraException, KuraNotConnectedException {
		if (m_mqttClient == null || !m_mqttClient.isConnected()) {
			throw new KuraNotConnectedException("Not connected");
		}

		s_logger.info("Publishing message on topic: {} with QoS: {}", topic, qos);

		MqttMessage message = new MqttMessage();
		message.setPayload(payload);
		message.setQos(qos);
		message.setRetained(retain);

		Integer messageId = null;
		try {
			IMqttDeliveryToken token = m_mqttClient.publish(topic, message);
			// At present Paho ALWAYS allocates (gets and increments) internally
			// a message ID,
			// even for messages published with QoS == 0.
			// Of course, for QoS == 0 this "internal" message ID will not hit
			// the wire.
			// On top of that, messages published with QoS == 0 are confirmed
			// in the deliveryComplete callback.
			// Another implementation might behave differently
			// and only allocate a message ID for messages published with QoS >
			// 0.
			// We don't want to rely on this and only return and confirm IDs
			// of messages published with QoS > 0.
			s_logger.debug("Published message with ID: {}", token.getMessageId());
			if (qos > 0) {
				messageId = Integer.valueOf(token.getMessageId());
			}
		} catch (MqttPersistenceException e) {
			// This is probably an unrecoverable internal error
			s_logger.error("Cannot publish on topic: {}", topic, e);
			throw new IllegalStateException("Cannot publish on topic: " + topic, e);
		} catch (MqttException e) {
			if (e.getReasonCode() == MqttException.REASON_CODE_MAX_INFLIGHT) {
				s_logger.info("Too many inflight messages");
				throw new KuraTooManyInflightMessagesException(e, "Too many in-fligh messages");
			} else {
				s_logger.error("Cannot publish on topic: " + topic, e);
				throw KuraException.internalError(e, "Cannot publish on topic: " + topic);
			}
		}

		DataTransportToken token = null;
		if (messageId != null) {
			token = new DataTransportToken(messageId, m_sessionId);
		}

		return token;
	}

	//==============================================================================
	// CloudConnectionStatus APIs
	//==============================================================================

	@Override
	public CloudConnectionStatusEnum getNotificationStatus() {
		return m_notificationStatus;
	}

	@Override
	public void setNotificationStatus(CloudConnectionStatusEnum status) {
		m_notificationStatus = status;
	}

	@Override
	public int getNotificationPriority() {
		return CloudConnectionStatusService.PRIORITY_MEDIUM;
	}
	
	//==============================================================================
	// SSL APIs
	//==============================================================================
	
	@Override
	public void onConfigurationUpdated() {
		update();
	}

	//==============================================================================
	// Private Methods
	//==============================================================================

	private void update() {
		boolean wasConnected = isConnected();

		// First notify the Listeners
		// We do nothing other than notifying the listeners which may later
		// request to disconnect and reconnect again.
		m_dataTransportListeners.onConfigurationUpdating(wasConnected);

		// Then update the configuration
		// Throwing a RuntimeException here is fine.
		// Listeners will not be notified of an invalid configuration update.
		s_logger.info("Building new configuration...");
		m_clientConf = buildConfiguration(m_properties);

		// We do nothing other than notifying the listeners which may later
		// request to disconnect and reconnect again.
		m_dataTransportListeners.onConfigurationUpdated(wasConnected);
	}

	private void setupMqttSession() {
		if(m_clientConf == null){
			throw new IllegalStateException("Invalid client configuration.");
		}

		m_newSession = false;

		//Close client if it is not null
		if(m_mqttClient != null){
			String brokerUrl = m_mqttClient.getServerURI();
			String clientId = m_mqttClient.getClientId();

			if(!(brokerUrl.equals(m_clientConf.getBrokerUrl()) && clientId.equals(m_clientConf.getClientId()))){
				try{
					s_logger.info("Closing client. Parameters have changed...");
					m_mqttClient.setCallback(null);
					m_mqttClient.close();
					m_newSession = true;
					s_logger.info("Client closed.");
				} catch(MqttException e){
					s_logger.error("Cannot close client", e);
				} finally {
					m_mqttClient = null;
				}
			}
		}

		if(m_mqttClient == null){
			s_logger.info("Creating a new client instance");

			MqttAsyncClient client = null;
			try {
				client = new MqttAsyncClient(m_clientConf.getBrokerUrl(), m_clientConf.getClientId(), new MemoryPersistence());
			} catch (MqttException e) {
				s_logger.error("Client instantiation failed", e);
				throw new IllegalStateException("Client instantiation failed", e);
			}

			client.setCallback(this);
			m_mqttClient = client;

		}

		m_sessionId = generateSessionId();
	}

	/**
	 * This method builds an internal configuration option needed by the client to connect
	 * @param properties
	 * @return
	 */
	private MqttClientConfiguration buildConfiguration(Map<String, Object> properties) {
		MqttClientConfiguration clientConfiguration;
		MqttConnectOptions conOpt = new MqttConnectOptions();
		String clientId = null;
		String brokerUrl = null;
		try {
			//Configure the Client ID
			clientId = (String) properties.get(MQTT_CLIENT_ID_PROP_NAME);
			ValidationUtil.notEmptyOrNull(clientId, "clientId");

			clientId = clientId.replace('/', '-').replace('+', '-').replace('#', '-');
			clientId.trim();

			//Configure Broker URL
			brokerUrl = (String) properties.get(MQTT_BROKER_URL_PROP_NAME);
			ValidationUtil.notEmptyOrNull(brokerUrl, MQTT_BROKER_URL_PROP_NAME);
			brokerUrl.trim();
			brokerUrl.replaceAll("/$", "");
			ValidationUtil.notEmptyOrNull(brokerUrl, "brokerUrl");

			ValidationUtil.notNegative((Integer) properties.get(MQTT_KEEP_ALIVE_PROP_NAME), MQTT_KEEP_ALIVE_PROP_NAME);

			String userName = (String) properties.get(MQTT_USERNAME_PROP_NAME);
			if(userName != null){
				conOpt.setUserName(userName);
			}

			char[] password = (char[]) properties.get(MQTT_PASSWORD_PROP_NAME);
			if(password != null){
				conOpt.setPassword(password);
			}

			conOpt.setKeepAliveInterval((Integer) properties.get(MQTT_KEEP_ALIVE_PROP_NAME));
			conOpt.setCleanSession(false);
			conOpt.setMqttVersion(4);

		} catch (KuraException e) {
			s_logger.error("Invalid configuration");
			throw new IllegalStateException("Invalid MQTT client configuration", e);
		}

		try {
			SSLSocketFactory ssf = m_sslManagerService.getSSLSocketFactory(null);
			conOpt.setSocketFactory(ssf);
		} catch (Exception e) {
			s_logger.error("SSL setup failed", e);
			throw new IllegalStateException("SSL setup failed", e);
		}

		clientConfiguration = new MqttClientConfiguration(brokerUrl, clientId, PersistenceType.MEMORY, conOpt);

		return clientConfiguration;
	}

	private void loadDataFromConnectionString(String connectionString){
		String[] attributes = connectionString.split(";");
		String hostname = null, deviceId = null, sharedAccessKey = null;
		for(String attr : attributes){
			if(attr.startsWith(HOSTNAME_ATTRIBUTE))
			{
				hostname = attr.substring(HOSTNAME_ATTRIBUTE.length());
			}
			else if (attr.startsWith(DEVICE_ID_ATTRIBUTE))
			{
				String urlEncodedDeviceId = attr.substring(DEVICE_ID_ATTRIBUTE.length());
				try
				{
					deviceId = URLDecoder.decode(urlEncodedDeviceId,StandardCharsets.UTF_8.name());
				}
				catch (UnsupportedEncodingException e)
				{
					throw new IllegalStateException(e);
				}
			}
			else if(attr.startsWith(SHARED_ACCESS_KEY_ATTRIBUTE))
			{
				sharedAccessKey = attr.substring(SHARED_ACCESS_KEY_ATTRIBUTE.length());
			}
		}

		if(hostname == null || deviceId == null || sharedAccessKey == null)
		{
			s_logger.error("Error loading properties from connection string.");
		}
		else
		{
			this.m_connectionString = connectionString;
			this.m_properties.put(HOSTNAME_ATTRIBUTE.substring(0, HOSTNAME_ATTRIBUTE.length()), hostname);
			this.m_properties.put(DEVICE_ID_ATTRIBUTE.substring(0, DEVICE_ID_ATTRIBUTE.length()), deviceId);
			this.m_properties.put(SHARED_ACCESS_KEY_ATTRIBUTE.substring(0, SHARED_ACCESS_KEY_ATTRIBUTE.length()), sharedAccessKey);

			String clientIdentifier;
			try {
				//TODO: Modify to get project name and version from configuration
				clientIdentifier = "DeviceClientType=" + URLEncoder.encode("org.eclipse.kura.core.data.transport.mqtt.AzureIotHubDataTransport" + "1.0.0", "UTF-8");
				String username = hostname + "/" + deviceId + "/" + clientIdentifier;
				String password = new IotHubSasToken(hostname + "/devices/" + deviceId, 
						deviceId, 
						sharedAccessKey, 
						System.currentTimeMillis() / 1000l + 60 + 1l).toString();
				this.m_properties.put(MQTT_BROKER_URL_PROP_NAME, SSL_SCHEME + hostname + ":" + PORT);
				this.m_properties.put(MQTT_USERNAME_PROP_NAME, username);
				this.m_properties.put(MQTT_PASSWORD_PROP_NAME, password.toCharArray());
				this.m_properties.put(MQTT_CLIENT_ID_PROP_NAME, deviceId);
			} catch (UnsupportedEncodingException e) {
				s_logger.error("Unsupported operation while encoding for the client identifier.");
			}
		}
	}

	private String generateSessionId() {
		return m_clientConf.getClientId() + "-" + m_clientConf.getBrokerUrl();
	}

}
