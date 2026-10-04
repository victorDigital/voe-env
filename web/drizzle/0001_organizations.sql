CREATE TABLE "account_key_envelope" (
	"credential_id" text PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"wrapped_key" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "audit_event" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text,
	"actor_id" text NOT NULL,
	"action" text NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "encryption_device" (
	"id" text PRIMARY KEY NOT NULL,
	"user_id" text,
	"public_key" text NOT NULL,
	"device_code_id" text NOT NULL,
	"session_id" text,
	"revoked" boolean DEFAULT false NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "encryption_device_device_code_id_unique" UNIQUE("device_code_id"),
	CONSTRAINT "encryption_device_session_id_unique" UNIQUE("session_id")
);
--> statement-breakpoint
CREATE TABLE "encryption_identity" (
	"user_id" text PRIMARY KEY NOT NULL,
	"public_key" text NOT NULL,
	"encrypted_private_key" text NOT NULL,
	"recovery_envelope" text NOT NULL,
	"recovery_auth_hash" text NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "invitation" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"email" text NOT NULL,
	"role" text NOT NULL,
	"status" text NOT NULL,
	"expires_at" timestamp NOT NULL,
	"inviter_id" text NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "legacy_migration" (
	"user_id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"source_digest" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"completed_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "member" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"user_id" text NOT NULL,
	"role" text NOT NULL,
	"created_at" timestamp NOT NULL,
	CONSTRAINT "member_org_user" UNIQUE("organization_id","user_id"),
	CONSTRAINT "member_role" CHECK ("member"."role" in ('owner','admin','member','viewer'))
);
--> statement-breakpoint
CREATE TABLE "organization" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"slug" text NOT NULL,
	"logo" text,
	"metadata" text,
	"created_at" timestamp NOT NULL,
	CONSTRAINT "organization_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "organization_key_envelope" (
	"organization_id" text NOT NULL,
	"recipient" text NOT NULL,
	"identity_binding" text NOT NULL,
	"epoch" integer NOT NULL,
	"wrapped_key" text NOT NULL,
	"provisioned_by" text NOT NULL,
	CONSTRAINT "organization_key_envelope_organization_id_recipient_pk" PRIMARY KEY("organization_id","recipient")
);
--> statement-breakpoint
CREATE TABLE "passkey" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text,
	"public_key" text NOT NULL,
	"user_id" text NOT NULL,
	"credential_id" text NOT NULL,
	"counter" integer NOT NULL,
	"device_type" text NOT NULL,
	"backed_up" boolean NOT NULL,
	"transports" text,
	"created_at" timestamp,
	"aaguid" text,
	CONSTRAINT "passkey_credential_id_unique" UNIQUE("credential_id")
);
--> statement-breakpoint
CREATE TABLE "passkey_verification" (
	"session_id" text PRIMARY KEY NOT NULL,
	"credential_id" text,
	"recovery" boolean DEFAULT false NOT NULL,
	"verified_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "vault_folder" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"parent_id" text,
	"name" text NOT NULL,
	"wrapped_key" text NOT NULL,
	CONSTRAINT "folder_org_id" UNIQUE("organization_id","id"),
	CONSTRAINT "folder_sibling" UNIQUE NULLS NOT DISTINCT("organization_id","parent_id","name"),
	CONSTRAINT "folder_name" CHECK (("vault_folder"."parent_id" is null and "vault_folder"."name" = '') or ("vault_folder"."parent_id" is not null and "vault_folder"."name" <> '' and position(':' in "vault_folder"."name") = 0))
);
--> statement-breakpoint
CREATE TABLE "vault_secret" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"folder_id" text NOT NULL,
	"name" text NOT NULL,
	"encrypted_value" text NOT NULL,
	CONSTRAINT "secret_folder_name" UNIQUE("folder_id","name")
);
--> statement-breakpoint
CREATE TABLE "workspace" (
	"organization_id" text PRIMARY KEY NOT NULL,
	"epoch" integer DEFAULT 1 NOT NULL,
	"revision" integer DEFAULT 0 NOT NULL,
	"rotation_required" boolean DEFAULT false NOT NULL
);
--> statement-breakpoint
ALTER TABLE "session" ADD COLUMN "active_organization_id" text;--> statement-breakpoint
ALTER TABLE "account_key_envelope" ADD CONSTRAINT "account_key_envelope_credential_id_passkey_credential_id_fk" FOREIGN KEY ("credential_id") REFERENCES "public"."passkey"("credential_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "account_key_envelope" ADD CONSTRAINT "account_key_envelope_user_id_encryption_identity_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."encryption_identity"("user_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_event" ADD CONSTRAINT "audit_event_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "encryption_device" ADD CONSTRAINT "encryption_device_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "encryption_device" ADD CONSTRAINT "encryption_device_session_id_session_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."session"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "encryption_identity" ADD CONSTRAINT "encryption_identity_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "invitation" ADD CONSTRAINT "invitation_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "invitation" ADD CONSTRAINT "invitation_inviter_id_user_id_fk" FOREIGN KEY ("inviter_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "legacy_migration" ADD CONSTRAINT "legacy_migration_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "legacy_migration" ADD CONSTRAINT "legacy_migration_organization_id_workspace_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."workspace"("organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "member" ADD CONSTRAINT "member_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "member" ADD CONSTRAINT "member_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "organization_key_envelope" ADD CONSTRAINT "organization_key_envelope_organization_id_workspace_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."workspace"("organization_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "organization_key_envelope" ADD CONSTRAINT "organization_key_envelope_provisioned_by_user_id_fk" FOREIGN KEY ("provisioned_by") REFERENCES "public"."user"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "passkey" ADD CONSTRAINT "passkey_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "passkey_verification" ADD CONSTRAINT "passkey_verification_session_id_session_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."session"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vault_folder" ADD CONSTRAINT "vault_folder_organization_id_workspace_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."workspace"("organization_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vault_folder" ADD CONSTRAINT "vault_folder_organization_id_parent_id_vault_folder_organization_id_id_fk" FOREIGN KEY ("organization_id","parent_id") REFERENCES "public"."vault_folder"("organization_id","id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vault_secret" ADD CONSTRAINT "vault_secret_organization_id_workspace_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."workspace"("organization_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vault_secret" ADD CONSTRAINT "vault_secret_organization_id_folder_id_vault_folder_organization_id_id_fk" FOREIGN KEY ("organization_id","folder_id") REFERENCES "public"."vault_folder"("organization_id","id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "workspace" ADD CONSTRAINT "workspace_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;