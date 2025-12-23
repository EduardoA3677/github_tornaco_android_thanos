.class public final enum Llyiahf/vczjk/d56;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/d56;

.field public static final enum OooOOO0:Llyiahf/vczjk/d56;

.field public static final enum OooOOOO:Llyiahf/vczjk/d56;

.field public static final enum OooOOOo:Llyiahf/vczjk/d56;

.field public static final synthetic OooOOo0:[Llyiahf/vczjk/d56;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    new-instance v0, Llyiahf/vczjk/d56;

    const-string v1, "SET"

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    new-instance v1, Llyiahf/vczjk/d56;

    const-string v2, "SKIP"

    const/4 v3, 0x1

    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v1, Llyiahf/vczjk/d56;->OooOOO0:Llyiahf/vczjk/d56;

    new-instance v2, Llyiahf/vczjk/d56;

    const-string v3, "FAIL"

    const/4 v4, 0x2

    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v2, Llyiahf/vczjk/d56;->OooOOO:Llyiahf/vczjk/d56;

    new-instance v3, Llyiahf/vczjk/d56;

    const-string v4, "AS_EMPTY"

    const/4 v5, 0x3

    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v3, Llyiahf/vczjk/d56;->OooOOOO:Llyiahf/vczjk/d56;

    new-instance v4, Llyiahf/vczjk/d56;

    const-string v5, "DEFAULT"

    const/4 v6, 0x4

    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v4, Llyiahf/vczjk/d56;->OooOOOo:Llyiahf/vczjk/d56;

    filled-new-array {v0, v1, v2, v3, v4}, [Llyiahf/vczjk/d56;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/d56;->OooOOo0:[Llyiahf/vczjk/d56;

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/d56;
    .locals 1

    const-class v0, Llyiahf/vczjk/d56;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/d56;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/d56;
    .locals 1

    sget-object v0, Llyiahf/vczjk/d56;->OooOOo0:[Llyiahf/vczjk/d56;

    invoke-virtual {v0}, [Llyiahf/vczjk/d56;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/d56;

    return-object v0
.end method
