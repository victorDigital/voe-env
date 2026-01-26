CREATE TABLE `deviceLog` (
	`id` text PRIMARY KEY NOT NULL,
	`userId` text NOT NULL,
	`clientId` text NOT NULL,
	`userCode` text NOT NULL,
	`scope` text,
	`approvedAt` text NOT NULL,
	FOREIGN KEY (`userId`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE no action
);
