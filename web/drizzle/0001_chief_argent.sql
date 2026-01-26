CREATE TABLE `env_path` (
	`id` text PRIMARY KEY NOT NULL,
	`userId` text NOT NULL,
	`path` text NOT NULL,
	`passwordHash` text NOT NULL,
	`createdAt` text NOT NULL,
	`updatedAt` text NOT NULL,
	FOREIGN KEY (`userId`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `env_path_userId_path_unique` ON `env_path` (`userId`,`path`);