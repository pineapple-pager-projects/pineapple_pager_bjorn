-- MySQL dump 10.13
-- Host: localhost    Database: webapp
-- Server version: 5.7.38

CREATE DATABASE IF NOT EXISTS `webapp`;
USE `webapp`;

CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(64) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(128) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

INSERT INTO `users` VALUES
(1, 'admin', '$2y$10$fakehashfakehashfakehashfakehashfakehashfake', 'admin@example.com'),
(2, 'user', '$2y$10$fakehashfakehashfakehashfakehashfakehashfake', 'user@example.com');
