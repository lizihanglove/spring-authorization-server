/*
SQLyog Ultimate v12.09 (64 bit)
MySQL - 5.7.36-log : Database - oauth2
*********************************************************************
*/


/*!40101 SET NAMES utf8 */;

/*!40101 SET SQL_MODE = ''*/;

/*!40014 SET @OLD_UNIQUE_CHECKS = @@UNIQUE_CHECKS, UNIQUE_CHECKS = 0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS = @@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS = 0 */;
/*!40101 SET @OLD_SQL_MODE = @@SQL_MODE, SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES = @@SQL_NOTES, SQL_NOTES = 0 */;
CREATE DATABASE /*!32312 IF NOT EXISTS */`oauth2` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin */;

USE `oauth2`;

/*Table structure for table `oauth2_authorization` */

DROP TABLE IF EXISTS `oauth2_authorization`;

CREATE TABLE `oauth2_authorization`
(
    `id`                            varchar(100) COLLATE utf8mb4_bin NOT NULL,
    `registered_client_id`          varchar(100) COLLATE utf8mb4_bin NOT NULL,
    `principal_name`                varchar(200) COLLATE utf8mb4_bin NOT NULL,
    `authorization_grant_type`      varchar(100) COLLATE utf8mb4_bin NOT NULL,
    `authorized_scopes`             varchar(1000)                    null,
    `attributes`                    text COLLATE utf8mb4_bin,
    `state`                         varchar(500) COLLATE utf8mb4_bin  DEFAULT NULL,
    `authorization_code_value`      varchar(1000) COLLATE utf8mb4_bin DEFAULT NULL,
    `authorization_code_issued_at`  datetime                          DEFAULT NULL,
    `authorization_code_expires_at` datetime                          DEFAULT NULL,
    `authorization_code_metadata`   text COLLATE utf8mb4_bin,
    `access_token_value`            varchar(1000) COLLATE utf8mb4_bin DEFAULT NULL,
    `access_token_issued_at`        datetime                          DEFAULT NULL,
    `access_token_expires_at`       datetime                          DEFAULT NULL,
    `access_token_metadata`         text COLLATE utf8mb4_bin,
    `access_token_type`             varchar(100) COLLATE utf8mb4_bin  DEFAULT NULL,
    `access_token_scopes`           varchar(1000) COLLATE utf8mb4_bin DEFAULT NULL,
    `oidc_id_token_value`           varchar(1000) COLLATE utf8mb4_bin DEFAULT NULL,
    `oidc_id_token_issued_at`       datetime                          DEFAULT NULL,
    `oidc_id_token_expires_at`      datetime                          DEFAULT NULL,
    `oidc_id_token_metadata`        text COLLATE utf8mb4_bin,
    `refresh_token_value`           varchar(1000) COLLATE utf8mb4_bin DEFAULT NULL,
    `refresh_token_issued_at`       datetime                          DEFAULT NULL,
    `refresh_token_expires_at`      datetime                          DEFAULT NULL,
    `refresh_token_metadata`        text COLLATE utf8mb4_bin,
    `created_at`                    datetime                         NOT NULL,
    `updated_at`                    datetime                         NOT NULL,
    PRIMARY KEY (`id`),
    KEY `idx_state` (`state`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

/*Data for the table `oauth2_authorization` */

insert into `oauth2_authorization`(`id`, `registered_client_id`, `principal_name`, `authorization_grant_type`,
                                   `attributes`, `state`, `authorization_code_value`, `authorization_code_issued_at`,
                                   `authorization_code_expires_at`, `authorization_code_metadata`, `access_token_value`,
                                   `access_token_issued_at`, `access_token_expires_at`, `access_token_metadata`,
                                   `access_token_type`, `access_token_scopes`, `oidc_id_token_value`,
                                   `oidc_id_token_issued_at`, `oidc_id_token_expires_at`, `oidc_id_token_metadata`,
                                   `refresh_token_value`, `refresh_token_issued_at`, `refresh_token_expires_at`,
                                   `refresh_token_metadata`, `created_at`, `updated_at`)
values ('2a267c08-5998-446d-a516-977d9249060a', 'client-1', 'user1', 'password',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"org.springframework.security.oauth2.server.authorization.OAuth2Authorization.AUTHORIZED_SCOPE\":[\"java.util.Collections$UnmodifiableSet\",[\"message.read\",\"message.write\"]]}',
        NULL, NULL, NULL, NULL, NULL,
        'eyJraWQiOiJlMjFjZTM1OS0zZGFmLTQzNDktOWYxNy1jYjgzMGE2ZjE2MTYiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImF1ZCI6Im1lc3NhZ2luZy1jbGllbnQiLCJuYmYiOjE2NTA0MzYzNjIsInNjb3BlIjpbIm1lc3NhZ2UucmVhZCIsIm1lc3NhZ2Uud3JpdGUiXSwiaXNzIjoiaHR0cDpcL1wvYXV0aC1zZXJ2ZXI6OTAwMCIsImV4cCI6MTY1MDQzNjY2MiwiaWF0IjoxNjUwNDM2MzYyfQ.Q1kwPQjKy46yybE5h-S_oOKyvT7qSt7UYC0FA6zgTa5O_dC2f9IRHwbn4dzngprGOUJGa4rwUlA5xqc5xLGUPbwpSGcEzd8WQBeyt17Zw8ALdtXkrxXZXAEdpDawXDT-58yxZBrDXUCTU7Kur-SY2_es3XKNNkn16nm5D4LHr5fIEokEhoRrClWCbqDfC90gZ3rYrWzpWRaAy9PElYo9-y8r9PcDUeta11SRCh0iultGK-P7z29GTA-ieGYTik66DvJfpNd8ozNSUc9iJRFcIu_3tc4Q_8TXMt23Kmj6XCcIBVoIhmCdrkmEMgZC0n73HFZ2-1nQNA7liHGSQ86wMg',
        '2022-04-20 14:32:43', '2022-04-20 14:37:43',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.claims\":{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"sub\":\"user1\",\"aud\":[\"java.util.Collections$SingletonList\",[\"messaging-client\"]],\"nbf\":[\"java.time.Instant\",1650436362.803000000],\"scope\":[\"java.util.Collections$UnmodifiableSet\",[\"message.read\",\"message.write\"]],\"iss\":[\"java.net.URL\",\"http://auth-server:9000\"],\"exp\":[\"java.time.Instant\",1650436662.803000000],\"iat\":[\"java.time.Instant\",1650436362.803000000]},\"metadata.token.invalidated\":false}',
        'Bearer', 'message.read,message.write', NULL, NULL, NULL, NULL,
        'C59gmIBTi9uGwIa5xxL7lkx4NT2LJXPVN2Jq7KNcqcyHwCX5E5eiBLnKH_llISBPdhkyYCCkHT0MJCWOi1J_N07asz_DT-eiloGkSTMHDih_JiHe9UXKUGYaK1Qz2qnL',
        '2022-04-20 14:32:47', '2022-04-20 15:32:47',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.invalidated\":false}',
        '2022-04-20 14:32:47', '2022-04-20 14:32:47'),
       ('390a81ec-5c19-42c9-b4ca-441c413a4709', 'client-1', 'user1', 'password',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"org.springframework.security.oauth2.server.authorization.OAuth2Authorization.AUTHORIZED_SCOPE\":[\"java.util.Collections$UnmodifiableSet\",[\"message.read\",\"message.write\"]]}',
        NULL, NULL, NULL, NULL, NULL,
        'eyJraWQiOiJhMjM5MGY0My1iYzY4LTRhMTUtYTU3Mi02Y2IzMjZmOWY1MWUiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImF1ZCI6Im1lc3NhZ2luZy1jbGllbnQiLCJuYmYiOjE2NTA0MzcwNDIsInNjb3BlIjpbIm1lc3NhZ2UucmVhZCIsIm1lc3NhZ2Uud3JpdGUiXSwiaXNzIjoiaHR0cDpcL1wvYXV0aC1zZXJ2ZXI6OTAwMCIsImV4cCI6MTY1MDQzNzM0MiwiaWF0IjoxNjUwNDM3MDQyfQ.KDtcdO45IfjhPHT6X8-IA3hY8yAmXoU97zlplLgUuG7u3TVQ8l0xEJeV5TqxQmM6S6EDtCkfc5sITgvXZIbLnUy0o2oz_6gw6ApBVm9uNeHwiKaQ1NUNQ7QhpYNz4VS1AO8HfeQnWCsb1bcGsHzH_v-bJ3tFnDS5Xk_f2_znex9uUhS1ogsasbRtGgt3aMWqlpLlmG8vBS9VjCUWp4oCDTWcF_gqavbIx0RBymrfW5Rx_LDxAgUYWCYk4WjREsIdb7NLy1VQ6q0ek2TWg-8QQbhv_PpwZbH95iQiq9kvSdXrTC7y68iUxFHykY6-Kg44QE4Zuoe7eoaZiF_JAvmZdg',
        '2022-04-20 14:44:03', '2022-04-20 14:49:03',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.claims\":{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"sub\":\"user1\",\"aud\":[\"java.util.Collections$SingletonList\",[\"messaging-client\"]],\"nbf\":[\"java.time.Instant\",1650437042.830000000],\"scope\":[\"java.util.Collections$UnmodifiableSet\",[\"message.read\",\"message.write\"]],\"iss\":[\"java.net.URL\",\"http://auth-server:9000\"],\"exp\":[\"java.time.Instant\",1650437342.830000000],\"iat\":[\"java.time.Instant\",1650437042.830000000]},\"metadata.token.invalidated\":false}',
        'Bearer', 'message.read,message.write', NULL, NULL, NULL, NULL,
        'bliTM3JNnweczxJdncsPoOYLuW0Sigi9Fnsch6SEVON2r37EzqS-6ydQHnm8SEye9MrBlAcaszOBGRTSnqIrvMs_JPrxdv33QSz85h75oiC1hHii-yV3aeSMvTyY-mgn',
        '2022-04-20 14:44:10', '2022-04-20 15:44:10',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.invalidated\":false}',
        '2022-04-20 14:44:27', '2022-04-20 14:44:27'),
       ('3f457924-d80a-4b78-b007-3ad77943b203', 'client-1', 'user1', 'password',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"org.springframework.security.oauth2.server.authorization.OAuth2Authorization.AUTHORIZED_SCOPE\":[\"java.util.LinkedHashSet\",[\"openid\"]]}',
        NULL, NULL, NULL, NULL, NULL,
        'eyJraWQiOiI0NWZkZWQ5MS1kNjA3LTQ3NTYtOWMyOS0zNzFjM2QyOTA1MzYiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImF1ZCI6Im1lc3NhZ2luZy1jbGllbnQiLCJuYmYiOjE2NTA0NTkyODYsInNjb3BlIjpbIm9wZW5pZCJdLCJpc3MiOiJodHRwOlwvXC9hdXRoLXNlcnZlcjo5MDAwIiwiZXhwIjoxNjUwNDU5NTg2LCJpYXQiOjE2NTA0NTkyODZ9.VA1Xvh7vpANEu72f0WG9MzkMOYEBKa0GyJ9ws03SWDAQXH4QEv_aYR-0kMDv2tm9WrefXJcT1dn65AV3eybm2TcElzCN-BEo-OrKcI2VO8jS6k5eGBQ1fW6fZCJCRxK3TZZvl4EUrMFCEkjuPw4a628Q-tZ5B94HluOb1MUUXv_T2HkaYw-U3HXPNPH0sSH3ogBrcl7fjt5dHjs1eWEjS71Xc47_XeiU3PfpaEue3-nABv2mL2A3pRHdufM9hpbKGWV4ReX9ZWyZSgQCkAx3bA4UdsVYfkzRUYXLOLh3GCjIb3am710Buae302BLAe3A-wFxd9nhUIEJLOosC7Sqkw',
        '2022-04-20 20:54:46', '2022-04-20 20:59:46',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.claims\":{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"sub\":\"user1\",\"aud\":[\"java.util.Collections$SingletonList\",[\"messaging-client\"]],\"nbf\":[\"java.time.Instant\",1650459286.413000000],\"scope\":[\"java.util.LinkedHashSet\",[\"openid\"]],\"iss\":[\"java.net.URL\",\"http://auth-server:9000\"],\"exp\":[\"java.time.Instant\",1650459586.413000000],\"iat\":[\"java.time.Instant\",1650459286.413000000]},\"metadata.token.invalidated\":false}',
        'Bearer', 'openid',
        'eyJraWQiOiI0NWZkZWQ5MS1kNjA3LTQ3NTYtOWMyOS0zNzFjM2QyOTA1MzYiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImF1ZCI6Im1lc3NhZ2luZy1jbGllbnQiLCJhenAiOiJtZXNzYWdpbmctY2xpZW50IiwiaXNzIjoiaHR0cDpcL1wvYXV0aC1zZXJ2ZXI6OTAwMCIsImV4cCI6MTY1MDQ2MTEyMiwiaWF0IjoxNjUwNDU5MzIyfQ.LF3YDdZ7hH3tBf0U3RtfVXnEadYrQe9oIsbtfcZJk2Ysg9M-b0giIcCycloIkd_HwmjacP7OAdDT9t0Pi09aWca5Ygdh1g5Rt1XEoBmF6MyCgAsF1NqzHI_jruaXvoyYU-CYsXdWJQrLjadjp1mW6KoRhL7T1m9oyXBGNqtpwSMztD3HvKoIVDuAfAj1aAckudyjWvT0ow-IGGHHctbI56yTz-fJKPsYJnhBbWSd-wWKkIAAEnDFoGabb8octQ1VdOTfqwDWDOww0UpqjOKPbdeNernjLOz9NehBni_Xn0j_dI-IXpaVFbuvCj1_8Ke9OyrzUtL-EKpAiH5xhnl-yg',
        '2022-04-20 20:55:23', '2022-04-20 21:25:23',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.claims\":{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"sub\":\"user1\",\"aud\":[\"java.util.Collections$SingletonList\",[\"messaging-client\"]],\"azp\":\"messaging-client\",\"iss\":[\"java.net.URL\",\"http://auth-server:9000\"],\"exp\":[\"java.time.Instant\",1650461122.978000000],\"iat\":[\"java.time.Instant\",1650459322.978000000]},\"metadata.token.invalidated\":false}',
        'nrvg3rqCxiU4PlTKES-iOheBTvDrmmO7-o13ZQzs4ziSEI1GfF24i-wtDEcpx3kgzGI2zziooo0noN5Rb2kew7FGe_ApskQn_Sm3-uPv1S2uJGs3iwBjcXrdOOiYPjYo',
        '2022-04-20 20:54:55', '2022-04-20 21:54:55',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.invalidated\":false}',
        '2022-04-20 20:56:39', '2022-04-20 20:56:39'),
       ('55f35820-36ae-4125-9f00-5cfb806ce3e6', 'client-1', 'user1', 'password',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"org.springframework.security.oauth2.server.authorization.OAuth2Authorization.AUTHORIZED_SCOPE\":[\"java.util.Collections$UnmodifiableSet\",[\"message.read\",\"message.write\"]]}',
        NULL, NULL, NULL, NULL, NULL,
        'eyJraWQiOiJjYmY1NjRhOC01MzI0LTQ0ZGItYmM0Ny0xMjhjZWZmYzk0ZDciLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImF1ZCI6Im1lc3NhZ2luZy1jbGllbnQiLCJuYmYiOjE2NTA0NTAzMDgsInNjb3BlIjpbIm1lc3NhZ2UucmVhZCIsIm1lc3NhZ2Uud3JpdGUiXSwiaXNzIjoiaHR0cDpcL1wvYXV0aC1zZXJ2ZXI6OTAwMCIsImV4cCI6MTY1MDQ1MDYwOCwiaWF0IjoxNjUwNDUwMzA4fQ.lAcGkuiQQjb-ZOR17pQjOUrg3aDviP--SNtJ_Jm5w-7nCIgivytR37CayopRSGWhbdfsZTvOqowlso25bmyC4n5-cb3rXfHuJE0t3_F8iLM2nN4eeVcruGRKxHvlc5VWr4sxaijFTqd9uscCyGP_H8VPJhas52gxjlvLPrdIkf_Zy9uriOJIV4QpysthfM0GsPxwlsdg7SvA2mkZKw-qTGFSlV8doCgBApqtlN6e-GJvJrsFgbzh7R_QMfRUSjmAfRLTBTo-SFEUO5eZV1zjtF6VRnqBGsi3KpiKa737okvHzvdMxRv3wuzIO81ZC3zft4iTnTjkLXlF7D4NlldksA',
        '2022-04-20 18:25:09', '2022-04-20 18:30:09',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.claims\":{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"sub\":\"user1\",\"aud\":[\"java.util.Collections$SingletonList\",[\"messaging-client\"]],\"nbf\":[\"java.time.Instant\",1650450308.863000000],\"scope\":[\"java.util.Collections$UnmodifiableSet\",[\"message.read\",\"message.write\"]],\"iss\":[\"java.net.URL\",\"http://auth-server:9000\"],\"exp\":[\"java.time.Instant\",1650450608.863000000],\"iat\":[\"java.time.Instant\",1650450308.863000000]},\"metadata.token.invalidated\":false}',
        'Bearer', 'message.read,message.write', NULL, NULL, NULL, NULL,
        'VC625nihLrMserhzRVooCYCD6lU58qFbJlA6iWjJL_i870DfoziEYiHjU7Xk7HERHFqypjc_fhqxwVMJ8YzrxMByY6RHuOkrEFCs_vUt9HJnwPthLnikpp1-YNb38H7A',
        '2022-04-20 18:25:09', '2022-04-20 19:25:09',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.invalidated\":false}',
        '2022-04-20 18:25:09', '2022-04-20 18:25:09'),
       ('571ebf95-bb9d-4601-a28e-5771b79c2a3b', 'client-1', 'messaging-client', 'client_credentials',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"org.springframework.security.oauth2.server.authorization.OAuth2Authorization.AUTHORIZED_SCOPE\":[\"java.util.Collections$UnmodifiableSet\",[\"message.read\",\"message.write\"]]}',
        NULL, NULL, NULL, NULL, NULL,
        'eyJraWQiOiI0NWZkZWQ5MS1kNjA3LTQ3NTYtOWMyOS0zNzFjM2QyOTA1MzYiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtZXNzYWdpbmctY2xpZW50IiwiYXVkIjoibWVzc2FnaW5nLWNsaWVudCIsIm5iZiI6MTY1MDQ1OTExNiwic2NvcGUiOlsibWVzc2FnZS5yZWFkIiwibWVzc2FnZS53cml0ZSJdLCJpc3MiOiJodHRwOlwvXC9hdXRoLXNlcnZlcjo5MDAwIiwiZXhwIjoxNjUwNDU5NDE2LCJpYXQiOjE2NTA0NTkxMTZ9.kIj3FfTQcQIYMDc4TBKOWjeHwP2YxyfbJTArzw7zrrZI8TidPDojaZfqdQmsKIpdOc2J1vSIhNSr5r_VtKklnVbp9Ii1hZSts9PWsmdCFfO1WASKk0BMOcwEa8u-FUIz4WdkDNDUYIkLpXG510pYe6LXj8ZiUrnPjhRCjNBUVonPFcqc7FTMl9xCupZk_JrOlsqOrvUYTuxxjajuW2baH3Kyep82tOEOUYBxQfblDPi3bcsBOKgnOLjQkKJKdmgAwiuQEWGB4JllaGn7vbjadzTiAC3rxH8_caIeImTO5ebfEUlKPAbPsZCPax9GfjtKd6UNVvY0UqJQAxplJaNoiQ',
        '2022-04-20 20:51:57', '2022-04-20 20:56:57',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.claims\":{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"sub\":\"messaging-client\",\"aud\":[\"java.util.Collections$SingletonList\",[\"messaging-client\"]],\"nbf\":[\"java.time.Instant\",1650459116.652000000],\"scope\":[\"java.util.Collections$UnmodifiableSet\",[\"message.read\",\"message.write\"]],\"iss\":[\"java.net.URL\",\"http://auth-server:9000\"],\"exp\":[\"java.time.Instant\",1650459416.652000000],\"iat\":[\"java.time.Instant\",1650459116.652000000]},\"metadata.token.invalidated\":false}',
        'Bearer', 'message.read,message.write', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2022-04-20 20:51:57',
        '2022-04-20 20:51:57'),
       ('5bc6efe5-80e8-4ceb-8a8e-e9a2bd2f62a7', 'client-1', 'user1', 'password',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"org.springframework.security.oauth2.server.authorization.OAuth2Authorization.AUTHORIZED_SCOPE\":[\"java.util.Collections$UnmodifiableSet\",[\"message.read\",\"message.write\"]]}',
        NULL, NULL, NULL, NULL, NULL,
        'eyJraWQiOiI5ZmRkMTllMi0wNTVhLTQ5Y2YtYWY1Yi1jNGFiMzdhMzUxYjciLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImF1ZCI6Im1lc3NhZ2luZy1jbGllbnQiLCJuYmYiOjE2NTA0MzQ5NzgsInNjb3BlIjpbIm1lc3NhZ2UucmVhZCIsIm1lc3NhZ2Uud3JpdGUiXSwiaXNzIjoiaHR0cDpcL1wvYXV0aC1zZXJ2ZXI6OTAwMCIsImV4cCI6MTY1MDQzNTI3OCwiaWF0IjoxNjUwNDM0OTc4fQ.aoQX-ysPv-rHtUL84Qpbhnxqo-Vrtfu4yC5g6okvQObDzxlP-AIPpIQvxRQu6l7FQdSt18O_sx6ugkJNkhNogIpZb3b7pIxkJvZ7rLlSVvJQHTI1Eanc9reaXaRCxPygLJZDQjdiCt6UA_jTzpwArOj-s5_aSwztrvDV2lOtOJc5y3Vl5wK4O7tV3Bamu5guPF1eT4zM0BRhV2oPN-VRU9D_US1dfCVj9ZZLiFHCaAApvIpVhCZREInWGwSxNPGgHZ6rUmKrlzo0DfXKzNx1WCH8ptpXgI_Bq6qgdmBuPGpbR4u-rjlGtru3vRKJ7lcizv87wSMuKOAFO_LISziQ_w',
        '2022-04-20 14:09:39', '2022-04-20 14:14:39',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.claims\":{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"sub\":\"user1\",\"aud\":[\"java.util.Collections$SingletonList\",[\"messaging-client\"]],\"nbf\":[\"java.time.Instant\",1650434978.522000000],\"scope\":[\"java.util.Collections$UnmodifiableSet\",[\"message.read\",\"message.write\"]],\"iss\":[\"java.net.URL\",\"http://auth-server:9000\"],\"exp\":[\"java.time.Instant\",1650435278.522000000],\"iat\":[\"java.time.Instant\",1650434978.522000000]},\"metadata.token.invalidated\":false}',
        'Bearer', 'message.read,message.write', NULL, NULL, NULL, NULL,
        'VknMUqxmLxBLs3qhCI-YoNq7-oLyypKY41VOVqpVVKrtLmK_5UX7wy_b7evAvE_n_mJD94Ewic64g0_neZKCkdzNJCS_IciVsQX9fyMbyqoLB8FYNxnwIYGXYR0nn00p',
        '2022-04-20 14:09:49', '2022-04-20 15:09:49',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.invalidated\":false}',
        '2022-04-20 14:10:00', '2022-04-20 14:10:00'),
       ('7d9938d9-9fb1-4a39-8a32-3de1ddcb7752', 'client-1', 'user1', 'authorization_code',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest\":{\"@class\":\"org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest\",\"authorizationUri\":\"http://localhost:9000/oauth2/authorize\",\"authorizationGrantType\":{\"value\":\"authorization_code\"},\"responseType\":{\"value\":\"code\"},\"clientId\":\"messaging-client\",\"redirectUri\":\"http://www.baidu.com\",\"scopes\":[\"java.util.Collections$UnmodifiableSet\",[]],\"state\":\"some-state\",\"additionalParameters\":{\"@class\":\"java.util.Collections$UnmodifiableMap\"},\"authorizationRequestUri\":\"http://localhost:9000/oauth2/authorize?response_type=code&client_id=messaging-client&state=some-state&redirect_uri=http://www.baidu.com\",\"attributes\":{\"@class\":\"java.util.Collections$UnmodifiableMap\"}},\"java.security.Principal\":{\"@class\":\"org.springframework.security.authentication.UsernamePasswordAuthenticationToken\",\"authorities\":[\"java.util.Collections$UnmodifiableRandomAccessList\",[{\"@class\":\"org.springframework.security.core.authority.SimpleGrantedAuthority\",\"authority\":\"ROLE_USER\"}]],\"details\":{\"@class\":\"org.springframework.security.web.authentication.WebAuthenticationDetails\",\"remoteAddress\":\"127.0.0.1\",\"sessionId\":\"305224BC7A1589165692FC15385BA649\"},\"authenticated\":true,\"principal\":{\"@class\":\"org.springframework.security.core.userdetails.User\",\"password\":null,\"username\":\"user1\",\"authorities\":[\"java.util.Collections$UnmodifiableSet\",[{\"@class\":\"org.springframework.security.core.authority.SimpleGrantedAuthority\",\"authority\":\"ROLE_USER\"}]],\"accountNonExpired\":true,\"accountNonLocked\":true,\"credentialsNonExpired\":true,\"enabled\":true},\"credentials\":null},\"org.springframework.security.oauth2.server.authorization.OAuth2Authorization.AUTHORIZED_SCOPE\":[\"java.util.Collections$UnmodifiableSet\",[]]}',
        NULL,
        'cjLZxOLWKfsTvbfJCeEk3qKS0PD-8lMcFj1HAZeOGHyI7wotnLLzYx91IPIv3t7_aFKjs3gytSWJJyh0R5PGpYXtwosi64WLkbQG28eL697kt1-snkesei1lzsmpPtJM',
        '2022-04-20 13:50:49', '2022-04-20 13:55:49',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.invalidated\":true}',
        'eyJraWQiOiI5ZmRkMTllMi0wNTVhLTQ5Y2YtYWY1Yi1jNGFiMzdhMzUxYjciLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImF1ZCI6Im1lc3NhZ2luZy1jbGllbnQiLCJuYmYiOjE2NTA0MzUwMzgsImlzcyI6Imh0dHA6XC9cL2F1dGgtc2VydmVyOjkwMDAiLCJleHAiOjE2NTA0MzUzMzgsImlhdCI6MTY1MDQzNTAzOH0.bw-w6oIKJzA66KK2peVv8tDKJffBQ3z1shh5lspvvKqhrDuZJ-tRnebeWdj9SPwh2VrTstjeo_uDUpICZMNwwqYZhwpwlG7zM8J1yoLBnOTqsMS1_jV2YIkS4XvIzLsEHjC0SONAnALfqDKAWCJoK4gVJcQ6JTPdfyvrkpBOWSqU1LrerM7QA8VuGCvtEvTnlOTpR3XdNR2kY2L-_vgbFrkTyQh1v6WRIc38d_X4JNJdfX5upRIzvxt0wJfYx-zt8e2QhbkidnC3gR5m2zADCO-98dx9rlcXNsa4vOjQXh2lAK1EFa9M-4zuaZ-ip7tnMisPiayBRhT8MskSRjPjkw',
        '2022-04-20 14:10:38', '2022-04-20 14:15:38',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.claims\":{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"sub\":\"user1\",\"aud\":[\"java.util.Collections$SingletonList\",[\"messaging-client\"]],\"nbf\":[\"java.time.Instant\",1650435038.492000000],\"iss\":[\"java.net.URL\",\"http://auth-server:9000\"],\"exp\":[\"java.time.Instant\",1650435338.492000000],\"iat\":[\"java.time.Instant\",1650435038.492000000]},\"metadata.token.invalidated\":false}',
        'Bearer', NULL, NULL, NULL, NULL, NULL,
        'Ggi3GJA8M9PWmmJ3cTX22o8Ib6Rjjp6eLHAppWtEWD5XNMI41-HJeKCsBmfaJjd2GKGrNHqrvAkPv3zT4vFTh6nn5CnGzvhSIyu4Hgch_bxe8ww6cUL_G5h8HWzYPbZu',
        '2022-04-20 13:51:34', '2022-04-20 14:51:34',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.invalidated\":false}',
        '2022-04-20 13:50:49', '2022-04-20 14:10:39'),
       ('8aabc333-9bcb-42ce-8ad6-743b0bf0faa9', 'client-1', 'user1', 'password',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"org.springframework.security.oauth2.server.authorization.OAuth2Authorization.AUTHORIZED_SCOPE\":[\"java.util.Collections$UnmodifiableSet\",[\"message.read\",\"message.write\"]]}',
        NULL, NULL, NULL, NULL, NULL,
        'eyJraWQiOiJlMjFjZTM1OS0zZGFmLTQzNDktOWYxNy1jYjgzMGE2ZjE2MTYiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImF1ZCI6Im1lc3NhZ2luZy1jbGllbnQiLCJuYmYiOjE2NTA0MzY0NjQsInNjb3BlIjpbIm1lc3NhZ2UucmVhZCIsIm1lc3NhZ2Uud3JpdGUiXSwiaXNzIjoiaHR0cDpcL1wvYXV0aC1zZXJ2ZXI6OTAwMCIsImV4cCI6MTY1MDQzNjc2NCwiaWF0IjoxNjUwNDM2NDY0fQ.wpPDyj1iNeWdOZtvOsJqVVcDK4MCRRqS-YX65FV6XFx2Kxjrqzi303WJ_-niVHRq4gFTkLwpqN0mQtQZvWLoIV7CDn1IFZCpeGTnXHfTLIcXv4nR6U-4dDAHV0U6LgMPSs84rxgi2mHdN8Bu-Vp5eUjCybM8aVNo6z5YKEgmY8PLiDd5d9zqK8RBSDLRS63fRAOx0DF1RmB6SVLzfr0NtgZY3Cvn-JyhzHGsfbafeQd2_CGoZEs5NKEGYOZ6IvX0cx1d6qAQRYEleDkaauFE6zUyOlUvU7qUOBvKC0lEQ8WJR5sh9ytNoeF5pMqu3lXap3JNdG2u7PSBFhfNO7JS6w',
        '2022-04-20 14:34:24', '2022-04-20 14:39:24',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.claims\":{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"sub\":\"user1\",\"aud\":[\"java.util.Collections$SingletonList\",[\"messaging-client\"]],\"nbf\":[\"java.time.Instant\",1650436464.316000000],\"scope\":[\"java.util.Collections$UnmodifiableSet\",[\"message.read\",\"message.write\"]],\"iss\":[\"java.net.URL\",\"http://auth-server:9000\"],\"exp\":[\"java.time.Instant\",1650436764.316000000],\"iat\":[\"java.time.Instant\",1650436464.316000000]},\"metadata.token.invalidated\":false}',
        'Bearer', 'message.read,message.write', NULL, NULL, NULL, NULL,
        'LKVcN0TyK1OgcTLpLK_ljUsWVWll40umwfrzotUmmSe5Z4WifaeEhTTVdNi0ax4zZiiVZFALFNaqSADmO4rcbmwCvFD2K2vkk-0uidsZ5jWBhW56cpk_LfhE7sqmFeFC',
        '2022-04-20 14:35:32', '2022-04-20 15:35:32',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.invalidated\":false}',
        '2022-04-20 14:36:01', '2022-04-20 14:36:01'),
       ('8d19a601-bff0-461c-a760-7ae6f6e7929f', 'client-1', 'user1', 'password',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"org.springframework.security.oauth2.server.authorization.OAuth2Authorization.AUTHORIZED_SCOPE\":[\"java.util.Collections$UnmodifiableSet\",[\"message.read\",\"message.write\"]]}',
        NULL, NULL, NULL, NULL, NULL,
        'eyJraWQiOiI0NWZkZWQ5MS1kNjA3LTQ3NTYtOWMyOS0zNzFjM2QyOTA1MzYiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImF1ZCI6Im1lc3NhZ2luZy1jbGllbnQiLCJuYmYiOjE2NTA0NTkxNTAsInNjb3BlIjpbIm1lc3NhZ2UucmVhZCIsIm1lc3NhZ2Uud3JpdGUiXSwiaXNzIjoiaHR0cDpcL1wvYXV0aC1zZXJ2ZXI6OTAwMCIsImV4cCI6MTY1MDQ1OTQ1MCwiaWF0IjoxNjUwNDU5MTUwfQ.D3h-WC5Q0s_S7LZgkl3WGYL34FIK2cNRyg6jIua4ObMNCdaPdILykS5sXFdr6VtckWQ9njffavEqasoVJeqGcTWZEcpqjnWXdL-gJcrYSlA8tL_fV5PYvQ4B5nvx7JuDt20G58c4JlnCQ5T9vhQJ6VbK3NIg2WGikoJyZRa9ZHXhXLTkn5EMcVObVKlAE0WII4fxfsnyWcgD5y7-FtWBsWx-NHlP3_zJyVHumZhCLxlCJ3Czjc6oPxMBnotHTdkCMNJjLH5TBwZehrG38NOctLk2rmluZ45NybiVV8_cfSmaFkYvmYEHDj1aBcNA2VMLOPI42f0idNLhZOk7xVKbqA',
        '2022-04-20 20:52:31', '2022-04-20 20:57:31',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.claims\":{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"sub\":\"user1\",\"aud\":[\"java.util.Collections$SingletonList\",[\"messaging-client\"]],\"nbf\":[\"java.time.Instant\",1650459150.816000000],\"scope\":[\"java.util.Collections$UnmodifiableSet\",[\"message.read\",\"message.write\"]],\"iss\":[\"java.net.URL\",\"http://auth-server:9000\"],\"exp\":[\"java.time.Instant\",1650459450.816000000],\"iat\":[\"java.time.Instant\",1650459150.816000000]},\"metadata.token.invalidated\":false}',
        'Bearer', 'message.read,message.write', NULL, NULL, NULL, NULL,
        'WzKFUqe_Vyy4SennXGRVoDYdRf4FcN3OvzjTTvTJxrqNv4GSN1XLiKrnF7IgyPeFuk1ro-EgTFsQGRkZLLaYiCJSAfhTkF-_HJBc6AGBhHHTsiqpxqRqZIAWUUCsxzI7',
        '2022-04-20 20:52:31', '2022-04-20 21:52:31',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.invalidated\":false}',
        '2022-04-20 20:52:31', '2022-04-20 20:52:31'),
       ('9230c524-0334-4fd5-801b-7b38926e2a03', 'client-1', 'user1', 'authorization_code',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest\":{\"@class\":\"org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest\",\"authorizationUri\":\"http://localhost:9000/oauth2/authorize\",\"authorizationGrantType\":{\"value\":\"authorization_code\"},\"responseType\":{\"value\":\"code\"},\"clientId\":\"messaging-client\",\"redirectUri\":\"http://www.baidu.com\",\"scopes\":[\"java.util.Collections$UnmodifiableSet\",[\"message.write\"]],\"state\":\"some-state\",\"additionalParameters\":{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"code_challenge\":\"23lwVh3xPX1ckZmTTzvoh6zY_L4gi2rvd4s9kKF9FQE\",\"code_challenge_method\":\"S256\"},\"authorizationRequestUri\":\"http://localhost:9000/oauth2/authorize?response_type=code&client_id=messaging-client&scope=message.write&state=some-state&redirect_uri=http://www.baidu.com&code_challenge=23lwVh3xPX1ckZmTTzvoh6zY_L4gi2rvd4s9kKF9FQE&code_challenge_method=S256\",\"attributes\":{\"@class\":\"java.util.Collections$UnmodifiableMap\"}},\"java.security.Principal\":{\"@class\":\"org.springframework.security.authentication.UsernamePasswordAuthenticationToken\",\"authorities\":[\"java.util.Collections$UnmodifiableRandomAccessList\",[{\"@class\":\"org.springframework.security.core.authority.SimpleGrantedAuthority\",\"authority\":\"ROLE_USER\"}]],\"details\":{\"@class\":\"org.springframework.security.web.authentication.WebAuthenticationDetails\",\"remoteAddress\":\"127.0.0.1\",\"sessionId\":\"1AFFDFB8E6CDF2DE61C38C406A7952E8\"},\"authenticated\":true,\"principal\":{\"@class\":\"org.springframework.security.core.userdetails.User\",\"password\":null,\"username\":\"user1\",\"authorities\":[\"java.util.Collections$UnmodifiableSet\",[{\"@class\":\"org.springframework.security.core.authority.SimpleGrantedAuthority\",\"authority\":\"ROLE_USER\"}]],\"accountNonExpired\":true,\"accountNonLocked\":true,\"credentialsNonExpired\":true,\"enabled\":true},\"credentials\":null},\"org.springframework.security.oauth2.server.authorization.OAuth2Authorization.AUTHORIZED_SCOPE\":[\"java.util.Collections$UnmodifiableSet\",[\"message.write\"]]}',
        NULL,
        '5rAsjANhJcyILdcc6WuSb27O5VHuE5fIBIurK8EdZw417ZDpcwb2ypN7RyNRdxccbjl9NaODMZcSmLuVEgeYSGCHlQULo65sq7_EIYTaLBxOoBGezejIcCH9_kztv3yp',
        '2022-04-20 14:15:49', '2022-04-20 14:20:49',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.invalidated\":true}',
        'eyJraWQiOiI5ZmRkMTllMi0wNTVhLTQ5Y2YtYWY1Yi1jNGFiMzdhMzUxYjciLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImF1ZCI6Im1lc3NhZ2luZy1jbGllbnQiLCJuYmYiOjE2NTA0MzUzODMsInNjb3BlIjpbIm1lc3NhZ2Uud3JpdGUiXSwiaXNzIjoiaHR0cDpcL1wvYXV0aC1zZXJ2ZXI6OTAwMCIsImV4cCI6MTY1MDQzNTY4MywiaWF0IjoxNjUwNDM1MzgzfQ.BaM8WDt9lqgBeOTizHdjViZz7u25u4vZapRpOT4vEVBPJs525Z1y2Lb9P4t07xmkfgKKnk_xkWYMV0YBVXSw6yZ3WP8woaVH12LOkaY7DuyZChLIwPqi-di98uPBz6SnvRzHjXAq9eruW5yoAHZO3axFg1--7Ft3UAxGyGAXrEp6_EJ4hXwyhu095ptz8BtDkReTfKM0Doi_2UeEhWVw3mRJS6zT5UcSWsqv5toxeRK8wtD5pNSc0hl80y6xAOUoUL16AKqeBahbELNZXoyRCfBNbyIBaQjj4fubXRH3QNsrWWc8_La9xetZO-9Wmeylx9myzNFn8jPPlXtmeEKtNQ',
        '2022-04-20 14:16:24', '2022-04-20 14:21:24',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.claims\":{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"sub\":\"user1\",\"aud\":[\"java.util.Collections$SingletonList\",[\"messaging-client\"]],\"nbf\":[\"java.time.Instant\",1650435383.615000000],\"scope\":[\"java.util.Collections$UnmodifiableSet\",[\"message.write\"]],\"iss\":[\"java.net.URL\",\"http://auth-server:9000\"],\"exp\":[\"java.time.Instant\",1650435683.615000000],\"iat\":[\"java.time.Instant\",1650435383.615000000]},\"metadata.token.invalidated\":false}',
        'Bearer', 'message.write', NULL, NULL, NULL, NULL,
        'odudZ-VpbY6V67NDE8X9tb45A2YXZG9NdvrpQCMEB3DNrEO379WLweRuWd9rvwKVZ578Ja6AFW3l5uCEqgTo_i4u0NoXrQh8aEXkNOte9dXF5xg1WOOnYUl6c-4ktgS_',
        '2022-04-20 14:16:26', '2022-04-20 15:16:26',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.invalidated\":false}',
        '2022-04-20 14:15:49', '2022-04-20 14:16:26'),
       ('9467f9b6-43ef-407f-b3fa-ac9c4c15d72d', 'client-1', 'user1', 'authorization_code',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"java.security.Principal\":{\"@class\":\"org.springframework.security.authentication.UsernamePasswordAuthenticationToken\",\"authorities\":[\"java.util.Collections$UnmodifiableRandomAccessList\",[{\"@class\":\"org.springframework.security.core.authority.SimpleGrantedAuthority\",\"authority\":\"ROLE_USER\"}]],\"details\":{\"@class\":\"org.springframework.security.web.authentication.WebAuthenticationDetails\",\"remoteAddress\":\"127.0.0.1\",\"sessionId\":\"1AFFDFB8E6CDF2DE61C38C406A7952E8\"},\"authenticated\":true,\"principal\":{\"@class\":\"org.springframework.security.core.userdetails.User\",\"password\":null,\"username\":\"user1\",\"authorities\":[\"java.util.Collections$UnmodifiableSet\",[{\"@class\":\"org.springframework.security.core.authority.SimpleGrantedAuthority\",\"authority\":\"ROLE_USER\"}]],\"accountNonExpired\":true,\"accountNonLocked\":true,\"credentialsNonExpired\":true,\"enabled\":true},\"credentials\":null},\"org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest\":{\"@class\":\"org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest\",\"authorizationUri\":\"http://localhost:9000/oauth2/authorize\",\"authorizationGrantType\":{\"value\":\"authorization_code\"},\"responseType\":{\"value\":\"code\"},\"clientId\":\"messaging-client\",\"redirectUri\":\"http://www.baidu.com\",\"scopes\":[\"java.util.Collections$UnmodifiableSet\",[\"message.write\"]],\"state\":\"some-state\",\"additionalParameters\":{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"code_challenge\":\"23lwVh3xPX1ckZmTTzvoh6zY_L4gi2rvd4s9kKF9FQE\",\"code_challenge_method\":\"S256\"},\"authorizationRequestUri\":\"http://localhost:9000/oauth2/authorize?response_type=code&client_id=messaging-client&scope=message.write&state=some-state&redirect_uri=http://www.baidu.com&code_challenge=23lwVh3xPX1ckZmTTzvoh6zY_L4gi2rvd4s9kKF9FQE&code_challenge_method=S256\",\"attributes\":{\"@class\":\"java.util.Collections$UnmodifiableMap\"}},\"org.springframework.security.oauth2.server.authorization.OAuth2Authorization.AUTHORIZED_SCOPE\":[\"java.util.Collections$UnmodifiableSet\",[\"message.write\"]]}',
        NULL,
        'V0wdNtZ7tzFynwcBChpGFQRcdcVJhd4muBqkQcV2IklyEk8T6QIvDy0Lcv4buMxc_zgnuy9gHhYD9COQPEuyXKz_lRtmNIbBOy4nbBty7cjUXvOINbcs5l2h_3FYxKcZ',
        '2022-04-20 14:13:35', '2022-04-20 14:18:35',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.invalidated\":false}', NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2022-04-20 14:13:35', '2022-04-20 14:13:35'),
       ('b307572e-0436-4254-a364-b47b3f35eaf5', 'client-1', 'user1', 'password',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"org.springframework.security.oauth2.server.authorization.OAuth2Authorization.AUTHORIZED_SCOPE\":[\"java.util.Collections$UnmodifiableSet\",[\"message.read\",\"message.write\"]]}',
        NULL, NULL, NULL, NULL, NULL,
        'eyJraWQiOiJhMjM5MGY0My1iYzY4LTRhMTUtYTU3Mi02Y2IzMjZmOWY1MWUiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImF1ZCI6Im1lc3NhZ2luZy1jbGllbnQiLCJuYmYiOjE2NTA0MzcwMTUsInNjb3BlIjpbIm1lc3NhZ2UucmVhZCIsIm1lc3NhZ2Uud3JpdGUiXSwiaXNzIjoiaHR0cDpcL1wvYXV0aC1zZXJ2ZXI6OTAwMCIsImV4cCI6MTY1MDQzNzMxNSwiaWF0IjoxNjUwNDM3MDE1fQ.M1GyG4i_CuwSsGow3VSGFqwzyvJvGKqRkdiO1G0ZIU8H2EvtbUOFeNQsIq828uEdQ8pZea9VoWczP6CkY0ZoPlCfziQlHA9FB_M-fj2y0rzPV6by9iTJP-q_dtigj4J72XEFE0-wHOuCaCofKhBSTwcc_yXLhJWorCKUXN1nPsf4TJgzRY2pjuoiw7q7AO33DZfglsZsIOLXHTTb11pjX6nkBxaribdT3nzx19TvTHzp3QO03LHr_0MASc3QhL3-pDWVlN1d5Rp5dbnKh3DtaUso_WE3zffWdH-NHZqTlX1m3wg_dBeTt4CpxnF2KX_TfDoDojwwYuGa4YNKjK7how',
        '2022-04-20 14:43:36', '2022-04-20 14:48:36',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.claims\":{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"sub\":\"user1\",\"aud\":[\"java.util.Collections$SingletonList\",[\"messaging-client\"]],\"nbf\":[\"java.time.Instant\",1650437015.574000000],\"scope\":[\"java.util.Collections$UnmodifiableSet\",[\"message.read\",\"message.write\"]],\"iss\":[\"java.net.URL\",\"http://auth-server:9000\"],\"exp\":[\"java.time.Instant\",1650437315.574000000],\"iat\":[\"java.time.Instant\",1650437015.574000000]},\"metadata.token.invalidated\":false}',
        'Bearer', 'message.read,message.write', NULL, NULL, NULL, NULL,
        'a1zWQfEdFe5Rx3lNn9qrKFCggf7ali7E9ME03LYA1J-xwvxbNysaQ--zOzvfVw8Byxegl1fS4ILpur8cV7V7y670ivAknwZuqsRYhkZJdYKxltGklRzrsvEAEkntoGWi',
        '2022-04-20 14:43:36', '2022-04-20 15:43:36',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.invalidated\":false}',
        '2022-04-20 14:43:36', '2022-04-20 14:43:36');

/*Table structure for table `oauth2_authorization_consent` */

DROP TABLE IF EXISTS `oauth2_authorization_consent`;

CREATE TABLE `oauth2_authorization_consent`
(
    `id`             bigint(20) unsigned              NOT NULL AUTO_INCREMENT,
    `client_id`      varchar(100) COLLATE utf8mb4_bin NOT NULL,
    `principal_name` varchar(200) COLLATE utf8mb4_bin NOT NULL,
    `created_at`     datetime                         NOT NULL,
    `authorities`    varchar(200) COLLATE utf8mb4_bin DEFAULT NULL,
    `updated_at`     datetime                         NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_client_id_princle_name` (`client_id`, `principal_name`)
) ENGINE = InnoDB
  AUTO_INCREMENT = 7
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

/*Data for the table `oauth2_authorization_consent` */

insert into `oauth2_authorization_consent`(`id`, `client_id`, `principal_name`, `created_at`, `authorities`,
                                           `updated_at`)
values (6, 'client-1', 'user1', '2022-03-18 22:10:56', 'SCOPE_message.write', '2022-03-18 22:10:56');

/*Table structure for table `oauth2_client` */

DROP TABLE IF EXISTS `oauth2_client`;

CREATE TABLE `oauth2_client`
(
    `id`                       varchar(100) COLLATE utf8mb4_bin NOT NULL,
    `client_id`                varchar(100) COLLATE utf8mb4_bin NOT NULL COMMENT '客户端id，唯一',
    `client_id_issued_at`      datetime                         NOT NULL,
    `client_secret`            varchar(200) COLLATE utf8mb4_bin DEFAULT NULL,
    `client_secret_expires_at` datetime                         DEFAULT NULL,
    `client_name`              varchar(200) COLLATE utf8mb4_bin NOT NULL,
    `client_icon`              varchar(400) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '应用图标',
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

/*Data for the table `oauth2_client` */

insert into `oauth2_client`(`id`, `client_id`, `client_id_issued_at`, `client_secret`, `client_secret_expires_at`,
                            `client_name`, `client_icon`)
values ('client-1', 'messaging-client', '2022-03-17 21:43:36', '{noop}secret', '2022-03-17 21:43:47', '测试', NULL);

/*Table structure for table `oauth2_client_authentication_method` */

DROP TABLE IF EXISTS `oauth2_client_authentication_method`;

CREATE TABLE `oauth2_client_authentication_method`
(
    `id`        bigint(20) unsigned              NOT NULL AUTO_INCREMENT,
    `client_id` varchar(100) COLLATE utf8mb4_bin NOT NULL,
    `method`    varchar(100) COLLATE utf8mb4_bin NOT NULL COMMENT '认证方法',
    PRIMARY KEY (`id`),
    KEY `idx_client_id` (`client_id`)
) ENGINE = InnoDB
  AUTO_INCREMENT = 8
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

/*Data for the table `oauth2_client_authentication_method` */

insert into `oauth2_client_authentication_method`(`id`, `client_id`, `method`)
values (1, 'messaging-client', 'client_secret_basic'),
       (2, 'messaging-client', 'basic'),
       (3, 'messaging-client', 'post'),
       (4, 'messaging-client', 'client_secret_post'),
       (5, 'messaging-client', 'client_secret_jwt'),
       (6, 'messaging-client', 'private_key_jwt'),
       (7, 'messaging-client', 'none');

/*Table structure for table `oauth2_client_authentication_scope` */

DROP TABLE IF EXISTS `oauth2_client_authentication_scope`;

CREATE TABLE `oauth2_client_authentication_scope`
(
    `id`        bigint(20) unsigned              NOT NULL AUTO_INCREMENT,
    `client_id` varchar(100) COLLATE utf8mb4_bin NOT NULL,
    `scope`     varchar(100) COLLATE utf8mb4_bin NOT NULL COMMENT 'scope',
    PRIMARY KEY (`id`),
    KEY `idx_client_id` (`client_id`)
) ENGINE = InnoDB
  AUTO_INCREMENT = 4
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

/*Data for the table `oauth2_client_authentication_scope` */

insert into `oauth2_client_authentication_scope`(`id`, `client_id`, `scope`)
values (1, 'messaging-client', 'message.read'),
       (2, 'messaging-client', 'message.write'),
       (3, 'messaging-client', 'openid');

/*Table structure for table `oauth2_client_authorization_grant_type` */

DROP TABLE IF EXISTS `oauth2_client_authorization_grant_type`;

CREATE TABLE `oauth2_client_authorization_grant_type`
(
    `id`         bigint(20) unsigned              NOT NULL AUTO_INCREMENT,
    `client_id`  varchar(100) COLLATE utf8mb4_bin NOT NULL,
    `grant_type` varchar(100) COLLATE utf8mb4_bin NOT NULL COMMENT '认证方法',
    PRIMARY KEY (`id`),
    KEY `idx_client_id` (`client_id`)
) ENGINE = InnoDB
  AUTO_INCREMENT = 5
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

/*Data for the table `oauth2_client_authorization_grant_type` */

insert into `oauth2_client_authorization_grant_type`(`id`, `client_id`, `grant_type`)
values (1, 'messaging-client', 'authorization_code'),
       (2, 'messaging-client', 'refresh_token'),
       (3, 'messaging-client', 'client_credentials'),
       (4, 'messaging-client', 'password');

/*Table structure for table `oauth2_client_redirect_uri` */

DROP TABLE IF EXISTS `oauth2_client_redirect_uri`;

CREATE TABLE `oauth2_client_redirect_uri`
(
    `id`           bigint(20) unsigned              NOT NULL AUTO_INCREMENT,
    `client_id`    varchar(100) COLLATE utf8mb4_bin NOT NULL,
    `redirect_uri` varchar(500) COLLATE utf8mb4_bin NOT NULL COMMENT 'scope',
    PRIMARY KEY (`id`),
    KEY `idx_client_id` (`client_id`)
) ENGINE = InnoDB
  AUTO_INCREMENT = 4
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_bin;

/*Data for the table `oauth2_client_redirect_uri` */

insert into `oauth2_client_redirect_uri`(`id`, `client_id`, `redirect_uri`)
values (1, 'messaging-client', 'http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc'),
       (2, 'messaging-client', 'http://127.0.0.1:8080/authorized'),
       (3, 'messaging-client', 'http://www.baidu.com');

/*Table structure for table `oauth2_client_setting` */

DROP TABLE IF EXISTS `oauth2_client_setting`;

CREATE TABLE `oauth2_client_setting`
(
    `id`         bigint(20)   NOT NULL AUTO_INCREMENT,
    `client_id`  varchar(60)  NOT NULL COMMENT 'client.client_id',
    `name`       varchar(255) NOT NULL,
    `value`      varchar(255) NOT NULL,
    `created_at` datetime     NOT NULL,
    PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB
  AUTO_INCREMENT = 4
  DEFAULT CHARSET = utf8mb4
  ROW_FORMAT = DYNAMIC;

/*Data for the table `oauth2_client_setting` */

insert into `oauth2_client_setting`(`id`, `client_id`, `name`, `value`, `created_at`)
values (1, 'messaging-client', 'settings.client.require-authorization-consent', 'true', '2022-03-17 21:06:06'),
       (2, 'messaging-client', 'settings.client.require-proof-key', 'false', '2022-03-17 23:15:34');

/*Table structure for table `oauth2_token_setting` */

DROP TABLE IF EXISTS `oauth2_token_setting`;

CREATE TABLE `oauth2_token_setting`
(
    `id`         bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    `client_id`  varchar(60)         NOT NULL COMMENT 'client.client_id',
    `name`       varchar(255)        NOT NULL,
    `value`      varchar(255)        NOT NULL,
    `created_at` datetime            NOT NULL,
    PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB
  AUTO_INCREMENT = 6
  DEFAULT CHARSET = utf8mb4
  ROW_FORMAT = DYNAMIC;

/*Data for the table `oauth2_token_setting` */

insert into `oauth2_token_setting`(`id`, `client_id`, `name`, `value`, `created_at`)
values (1, 'messaging-client', 'settings.token.reuse-refresh-tokens', 'true', '2022-03-17 23:49:34'),
       (2, 'messaging-client', 'settings.token.id-token-signature-algorithm', 'RS256', '2022-03-17 23:49:57'),
       (3, 'messaging-client', 'settings.token.access-token-time-to-live', '300', '2022-03-17 23:50:29'),
       (4, 'messaging-client', 'settings.token.refresh-token-time-to-live', '3600', '2022-03-17 23:50:38'),
       (5, 'messaging-client', 'settings.token.access-token-format', 'self-contained', '2022-04-20 00:10:47'),
       (6, 'messaging-client', 'settings.token.authorization-code-time-to-live', '3600', '2023-04-02 18:38:47');

/*!40101 SET SQL_MODE = @OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS = @OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS = @OLD_UNIQUE_CHECKS */;
/*!40111 SET SQL_NOTES = @OLD_SQL_NOTES */;
