.class public abstract Llyiahf/vczjk/tu7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/uu7;


# instance fields
.field private final identityHash:Ljava/lang/String;

.field private final legacyIdentityHash:Ljava/lang/String;

.field private final version:I


# direct methods
.method public constructor <init>(ILjava/lang/String;Ljava/lang/String;)V
    .locals 1

    const-string v0, "identityHash"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "legacyIdentityHash"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Llyiahf/vczjk/tu7;->version:I

    iput-object p2, p0, Llyiahf/vczjk/tu7;->identityHash:Ljava/lang/String;

    iput-object p3, p0, Llyiahf/vczjk/tu7;->legacyIdentityHash:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public abstract createAllTables(Llyiahf/vczjk/j48;)V
.end method

.method public abstract dropAllTables(Llyiahf/vczjk/j48;)V
.end method

.method public final getIdentityHash()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tu7;->identityHash:Ljava/lang/String;

    return-object v0
.end method

.method public final getLegacyIdentityHash()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tu7;->legacyIdentityHash:Ljava/lang/String;

    return-object v0
.end method

.method public final getVersion()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/tu7;->version:I

    return v0
.end method

.method public abstract onCreate(Llyiahf/vczjk/j48;)V
.end method

.method public abstract onOpen(Llyiahf/vczjk/j48;)V
.end method

.method public abstract onPostMigrate(Llyiahf/vczjk/j48;)V
.end method

.method public abstract onPreMigrate(Llyiahf/vczjk/j48;)V
.end method

.method public abstract onValidateSchema(Llyiahf/vczjk/j48;)Llyiahf/vczjk/su7;
.end method
