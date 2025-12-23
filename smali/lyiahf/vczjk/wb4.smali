.class public final enum Llyiahf/vczjk/wb4;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/wb4;

.field public static final enum OooOOO0:Llyiahf/vczjk/wb4;

.field public static final enum OooOOOO:Llyiahf/vczjk/wb4;

.field public static final synthetic OooOOOo:[Llyiahf/vczjk/wb4;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    new-instance v0, Llyiahf/vczjk/wb4;

    const-string v1, "DYNAMIC"

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/wb4;->OooOOO0:Llyiahf/vczjk/wb4;

    new-instance v1, Llyiahf/vczjk/wb4;

    const-string v2, "STATIC"

    const/4 v3, 0x1

    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v1, Llyiahf/vczjk/wb4;->OooOOO:Llyiahf/vczjk/wb4;

    new-instance v2, Llyiahf/vczjk/wb4;

    const-string v3, "DEFAULT_TYPING"

    const/4 v4, 0x2

    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v2, Llyiahf/vczjk/wb4;->OooOOOO:Llyiahf/vczjk/wb4;

    filled-new-array {v0, v1, v2}, [Llyiahf/vczjk/wb4;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/wb4;->OooOOOo:[Llyiahf/vczjk/wb4;

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/wb4;
    .locals 1

    const-class v0, Llyiahf/vczjk/wb4;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/wb4;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/wb4;
    .locals 1

    sget-object v0, Llyiahf/vczjk/wb4;->OooOOOo:[Llyiahf/vczjk/wb4;

    invoke-virtual {v0}, [Llyiahf/vczjk/wb4;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/wb4;

    return-object v0
.end method
