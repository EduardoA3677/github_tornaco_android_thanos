.class public final enum Llyiahf/vczjk/vb4;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final synthetic OooOOO:[Llyiahf/vczjk/vb4;

.field public static final enum OooOOO0:Llyiahf/vczjk/vb4;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    new-instance v0, Llyiahf/vczjk/vb4;

    const-string v1, "ALWAYS"

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    new-instance v1, Llyiahf/vczjk/vb4;

    const-string v2, "NON_NULL"

    const/4 v3, 0x1

    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    new-instance v2, Llyiahf/vczjk/vb4;

    const-string v3, "NON_DEFAULT"

    const/4 v4, 0x2

    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    new-instance v3, Llyiahf/vczjk/vb4;

    const-string v4, "NON_EMPTY"

    const/4 v5, 0x3

    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    new-instance v4, Llyiahf/vczjk/vb4;

    const-string v5, "DEFAULT_INCLUSION"

    const/4 v6, 0x4

    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v4, Llyiahf/vczjk/vb4;->OooOOO0:Llyiahf/vczjk/vb4;

    filled-new-array {v0, v1, v2, v3, v4}, [Llyiahf/vczjk/vb4;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/vb4;->OooOOO:[Llyiahf/vczjk/vb4;

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/vb4;
    .locals 1

    const-class v0, Llyiahf/vczjk/vb4;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/vb4;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/vb4;
    .locals 1

    sget-object v0, Llyiahf/vczjk/vb4;->OooOOO:[Llyiahf/vczjk/vb4;

    invoke-virtual {v0}, [Llyiahf/vczjk/vb4;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/vb4;

    return-object v0
.end method
