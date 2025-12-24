//! MQTT protocol types
pub const MQTT_KEYWORDS: &[&str] = &["mqtt.connect.clientid", "mqtt.connect.username", "mqtt.connect.password", "mqtt.connect.willtopic", "mqtt.connect.willmessage", "mqtt.connack.return_code", "mqtt.publish.topic", "mqtt.publish.message", "mqtt.subscribe.topic", "mqtt.unsubscribe.topic", "mqtt.protocol_version", "mqtt.type", "mqtt.flags", "mqtt.qos"];

pub const MQTT_PACKET_TYPES: &[&str] = &["CONNECT", "CONNACK", "PUBLISH", "PUBACK", "PUBREC", "PUBREL", "PUBCOMP", "SUBSCRIBE", "SUBACK", "UNSUBSCRIBE", "UNSUBACK", "PINGREQ", "PINGRESP", "DISCONNECT", "AUTH"];

pub const SUSPICIOUS_TOPICS: &[&str] = &["$SYS/", "#", "+", "../"];
