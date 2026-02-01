CREATE TABLE "account" (
	"id" text PRIMARY KEY NOT NULL,
	"account_id" text NOT NULL,
	"provider_id" text NOT NULL,
	"user_id" text NOT NULL,
	"access_token" text,
	"refresh_token" text,
	"id_token" text,
	"access_token_expires_at" timestamp,
	"refresh_token_expires_at" timestamp,
	"scope" text,
	"password" text,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp NOT NULL
);
--> statement-breakpoint
CREATE TABLE "deviceCode" (
	"id" text PRIMARY KEY NOT NULL,
	"deviceCode" text NOT NULL,
	"userCode" text NOT NULL,
	"userId" text,
	"clientId" text,
	"scope" text,
	"status" text NOT NULL,
	"expiresAt" timestamp NOT NULL,
	"lastPolledAt" timestamp,
	"pollingInterval" integer,
	"createdAt" timestamp DEFAULT now() NOT NULL,
	"updatedAt" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "deviceLog" (
	"id" text PRIMARY KEY NOT NULL,
	"userId" text NOT NULL,
	"clientId" text NOT NULL,
	"userCode" text NOT NULL,
	"scope" text,
	"approvedAt" timestamp NOT NULL
);
--> statement-breakpoint
CREATE TABLE "env_vault" (
	"id" text PRIMARY KEY NOT NULL,
	"userId" text NOT NULL,
	"fullKey" text NOT NULL,
	"encryptedValue" text NOT NULL,
	"createdAt" timestamp DEFAULT now() NOT NULL,
	"updatedAt" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "env_vault_userId_fullKey_unique" UNIQUE("userId","fullKey")
);
--> statement-breakpoint
CREATE TABLE "folder_shares" (
	"id" text PRIMARY KEY NOT NULL,
	"ownerId" text NOT NULL,
	"sharedWithId" text NOT NULL,
	"folderPath" text NOT NULL,
	"permission" text NOT NULL,
	"encryptedVaultPassword" text NOT NULL,
	"createdAt" timestamp DEFAULT now() NOT NULL,
	"expiresAt" timestamp,
	CONSTRAINT "folder_shares_unique" UNIQUE("ownerId","sharedWithId","folderPath")
);
--> statement-breakpoint
CREATE TABLE "session" (
	"id" text PRIMARY KEY NOT NULL,
	"expires_at" timestamp NOT NULL,
	"token" text NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp NOT NULL,
	"ip_address" text,
	"user_agent" text,
	"user_id" text NOT NULL,
	CONSTRAINT "session_token_unique" UNIQUE("token")
);
--> statement-breakpoint
CREATE TABLE "user" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"email" text NOT NULL,
	"email_verified" boolean DEFAULT false NOT NULL,
	"image" text,
	"public_key" text,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "user_email_unique" UNIQUE("email")
);
--> statement-breakpoint
CREATE TABLE "verification" (
	"id" text PRIMARY KEY NOT NULL,
	"identifier" text NOT NULL,
	"value" text NOT NULL,
	"expires_at" timestamp NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "account" ADD CONSTRAINT "account_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "deviceCode" ADD CONSTRAINT "deviceCode_userId_user_id_fk" FOREIGN KEY ("userId") REFERENCES "public"."user"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "deviceLog" ADD CONSTRAINT "deviceLog_userId_user_id_fk" FOREIGN KEY ("userId") REFERENCES "public"."user"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "env_vault" ADD CONSTRAINT "env_vault_userId_user_id_fk" FOREIGN KEY ("userId") REFERENCES "public"."user"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "folder_shares" ADD CONSTRAINT "folder_shares_ownerId_user_id_fk" FOREIGN KEY ("ownerId") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "folder_shares" ADD CONSTRAINT "folder_shares_sharedWithId_user_id_fk" FOREIGN KEY ("sharedWithId") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "session" ADD CONSTRAINT "session_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "account_userId_idx" ON "account" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "folder_shares_ownerId_idx" ON "folder_shares" USING btree ("ownerId");--> statement-breakpoint
CREATE INDEX "folder_shares_sharedWithId_idx" ON "folder_shares" USING btree ("sharedWithId");--> statement-breakpoint
CREATE INDEX "session_userId_idx" ON "session" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "verification_identifier_idx" ON "verification" USING btree ("identifier");