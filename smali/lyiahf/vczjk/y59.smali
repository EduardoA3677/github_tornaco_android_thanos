.class public final enum Llyiahf/vczjk/y59;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/y59;

.field public static final OooOOO0:Llyiahf/vczjk/uk2;

.field public static final enum OooOOOO:Llyiahf/vczjk/y59;

.field public static final enum OooOOOo:Llyiahf/vczjk/y59;

.field public static final synthetic OooOOo:[Llyiahf/vczjk/y59;

.field public static final enum OooOOo0:Llyiahf/vczjk/y59;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Llyiahf/vczjk/y59;

    const-string v1, "EXTERNAL"

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/y59;->OooOOO:Llyiahf/vczjk/y59;

    new-instance v1, Llyiahf/vczjk/y59;

    const-string v2, "DATA"

    const/4 v3, 0x1

    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v1, Llyiahf/vczjk/y59;->OooOOOO:Llyiahf/vczjk/y59;

    new-instance v2, Llyiahf/vczjk/y59;

    const-string v3, "SD_CARD"

    const/4 v4, 0x2

    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v2, Llyiahf/vczjk/y59;->OooOOOo:Llyiahf/vczjk/y59;

    new-instance v3, Llyiahf/vczjk/y59;

    const-string v4, "UNKNOWN"

    const/4 v5, 0x3

    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v3, Llyiahf/vczjk/y59;->OooOOo0:Llyiahf/vczjk/y59;

    filled-new-array {v0, v1, v2, v3}, [Llyiahf/vczjk/y59;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/y59;->OooOOo:[Llyiahf/vczjk/y59;

    invoke-static {v0}, Llyiahf/vczjk/yi4;->OoooO0([Ljava/lang/Enum;)Llyiahf/vczjk/np2;

    new-instance v0, Llyiahf/vczjk/uk2;

    const/16 v1, 0x19

    invoke-direct {v0, v1}, Llyiahf/vczjk/uk2;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/y59;->OooOOO0:Llyiahf/vczjk/uk2;

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/y59;
    .locals 1

    const-class v0, Llyiahf/vczjk/y59;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/y59;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/y59;
    .locals 1

    sget-object v0, Llyiahf/vczjk/y59;->OooOOo:[Llyiahf/vczjk/y59;

    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/y59;

    return-object v0
.end method
