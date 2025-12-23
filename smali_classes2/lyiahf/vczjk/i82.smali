.class public final enum Llyiahf/vczjk/i82;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/i82;

.field public static final enum OooOOO0:Llyiahf/vczjk/i82;

.field public static final synthetic OooOOOO:[Llyiahf/vczjk/i82;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    new-instance v0, Llyiahf/vczjk/i82;

    const-string v1, "STABLE"

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/i82;->OooOOO0:Llyiahf/vczjk/i82;

    new-instance v1, Llyiahf/vczjk/i82;

    const-string v2, "UNSTABLE"

    const/4 v3, 0x1

    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v1, Llyiahf/vczjk/i82;->OooOOO:Llyiahf/vczjk/i82;

    filled-new-array {v0, v1}, [Llyiahf/vczjk/i82;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/i82;->OooOOOO:[Llyiahf/vczjk/i82;

    invoke-static {v0}, Llyiahf/vczjk/yi4;->OoooO0([Ljava/lang/Enum;)Llyiahf/vczjk/np2;

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/i82;
    .locals 1

    const-class v0, Llyiahf/vczjk/i82;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/i82;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/i82;
    .locals 1

    sget-object v0, Llyiahf/vczjk/i82;->OooOOOO:[Llyiahf/vczjk/i82;

    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/i82;

    return-object v0
.end method
