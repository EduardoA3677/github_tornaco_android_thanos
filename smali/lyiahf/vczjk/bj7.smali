.class public final enum Llyiahf/vczjk/bj7;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/bj7;

.field public static final enum OooOOO0:Llyiahf/vczjk/bj7;

.field public static final enum OooOOOO:Llyiahf/vczjk/bj7;

.field public static final enum OooOOOo:Llyiahf/vczjk/bj7;

.field public static final enum OooOOo:Llyiahf/vczjk/bj7;

.field public static final enum OooOOo0:Llyiahf/vczjk/bj7;

.field public static final synthetic OooOOoo:[Llyiahf/vczjk/bj7;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    new-instance v0, Llyiahf/vczjk/bj7;

    const-string v1, "ShutDown"

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/bj7;->OooOOO0:Llyiahf/vczjk/bj7;

    new-instance v1, Llyiahf/vczjk/bj7;

    const-string v2, "ShuttingDown"

    const/4 v3, 0x1

    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v1, Llyiahf/vczjk/bj7;->OooOOO:Llyiahf/vczjk/bj7;

    new-instance v2, Llyiahf/vczjk/bj7;

    const-string v3, "Inactive"

    const/4 v4, 0x2

    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v2, Llyiahf/vczjk/bj7;->OooOOOO:Llyiahf/vczjk/bj7;

    new-instance v3, Llyiahf/vczjk/bj7;

    const-string v4, "InactivePendingWork"

    const/4 v5, 0x3

    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v3, Llyiahf/vczjk/bj7;->OooOOOo:Llyiahf/vczjk/bj7;

    new-instance v4, Llyiahf/vczjk/bj7;

    const-string v5, "Idle"

    const/4 v6, 0x4

    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v4, Llyiahf/vczjk/bj7;->OooOOo0:Llyiahf/vczjk/bj7;

    new-instance v5, Llyiahf/vczjk/bj7;

    const-string v6, "PendingWork"

    const/4 v7, 0x5

    invoke-direct {v5, v6, v7}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v5, Llyiahf/vczjk/bj7;->OooOOo:Llyiahf/vczjk/bj7;

    filled-new-array/range {v0 .. v5}, [Llyiahf/vczjk/bj7;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/bj7;->OooOOoo:[Llyiahf/vczjk/bj7;

    invoke-static {v0}, Llyiahf/vczjk/yi4;->OoooO0([Ljava/lang/Enum;)Llyiahf/vczjk/np2;

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/bj7;
    .locals 1

    const-class v0, Llyiahf/vczjk/bj7;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/bj7;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/bj7;
    .locals 1

    sget-object v0, Llyiahf/vczjk/bj7;->OooOOoo:[Llyiahf/vczjk/bj7;

    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/bj7;

    return-object v0
.end method
