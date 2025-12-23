.class public final enum Llyiahf/vczjk/c03;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final synthetic OooOOO:[Llyiahf/vczjk/c03;

.field public static final enum OooOOO0:Llyiahf/vczjk/c03;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/c03;

    const-string v1, "APPEND"

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/c03;->OooOOO0:Llyiahf/vczjk/c03;

    filled-new-array {v0}, [Llyiahf/vczjk/c03;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/c03;->OooOOO:[Llyiahf/vczjk/c03;

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/c03;
    .locals 1

    const-class v0, Llyiahf/vczjk/c03;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/c03;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/c03;
    .locals 1

    sget-object v0, Llyiahf/vczjk/c03;->OooOOO:[Llyiahf/vczjk/c03;

    invoke-virtual {v0}, [Llyiahf/vczjk/c03;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/c03;

    return-object v0
.end method
