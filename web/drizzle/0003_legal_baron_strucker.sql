CREATE TABLE "folder_shares" (
	"id" text PRIMARY KEY NOT NULL,
	"ownerId" text NOT NULL,
	"sharedWithId" text NOT NULL,
	"folderPath" text NOT NULL,
	"permission" text NOT NULL,
	"vaultPassword" text NOT NULL,
	"createdAt" timestamp DEFAULT now() NOT NULL,
	"expiresAt" timestamp,
	CONSTRAINT "folder_shares_unique" UNIQUE("ownerId","sharedWithId","folderPath")
);
--> statement-breakpoint
ALTER TABLE "folder_shares" ADD CONSTRAINT "folder_shares_ownerId_user_id_fk" FOREIGN KEY ("ownerId") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "folder_shares" ADD CONSTRAINT "folder_shares_sharedWithId_user_id_fk" FOREIGN KEY ("sharedWithId") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "folder_shares_ownerId_idx" ON "folder_shares" USING btree ("ownerId");--> statement-breakpoint
CREATE INDEX "folder_shares_sharedWithId_idx" ON "folder_shares" USING btree ("sharedWithId");