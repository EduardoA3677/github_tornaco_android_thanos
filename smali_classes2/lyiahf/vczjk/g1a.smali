.class public final enum Llyiahf/vczjk/g1a;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/g1a;

.field public static final enum OooOOO0:Llyiahf/vczjk/g1a;

.field public static final enum OooOOOO:Llyiahf/vczjk/g1a;

.field public static final enum OooOOOo:Llyiahf/vczjk/g1a;

.field public static final synthetic OooOOo0:[Llyiahf/vczjk/g1a;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Llyiahf/vczjk/g1a;

    const-string v1, "SUCCESSFUL"

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/g1a;->OooOOO0:Llyiahf/vczjk/g1a;

    new-instance v1, Llyiahf/vczjk/g1a;

    const-string v2, "REREGISTER"

    const/4 v3, 0x1

    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v1, Llyiahf/vczjk/g1a;->OooOOO:Llyiahf/vczjk/g1a;

    new-instance v2, Llyiahf/vczjk/g1a;

    const-string v3, "CANCELLED"

    const/4 v4, 0x2

    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v2, Llyiahf/vczjk/g1a;->OooOOOO:Llyiahf/vczjk/g1a;

    new-instance v3, Llyiahf/vczjk/g1a;

    const-string v4, "ALREADY_SELECTED"

    const/4 v5, 0x3

    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v3, Llyiahf/vczjk/g1a;->OooOOOo:Llyiahf/vczjk/g1a;

    filled-new-array {v0, v1, v2, v3}, [Llyiahf/vczjk/g1a;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/g1a;->OooOOo0:[Llyiahf/vczjk/g1a;

    invoke-static {v0}, Llyiahf/vczjk/yi4;->OoooO0([Ljava/lang/Enum;)Llyiahf/vczjk/np2;

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/g1a;
    .locals 1

    const-class v0, Llyiahf/vczjk/g1a;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/g1a;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/g1a;
    .locals 1

    sget-object v0, Llyiahf/vczjk/g1a;->OooOOo0:[Llyiahf/vczjk/g1a;

    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/g1a;

    return-object v0
.end method
