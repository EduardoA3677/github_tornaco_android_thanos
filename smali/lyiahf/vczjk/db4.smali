.class public final enum Llyiahf/vczjk/db4;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/db4;

.field public static final enum OooOOO0:Llyiahf/vczjk/db4;

.field public static final enum OooOOOO:Llyiahf/vczjk/db4;

.field public static final enum OooOOOo:Llyiahf/vczjk/db4;

.field public static final enum OooOOo:Llyiahf/vczjk/db4;

.field public static final enum OooOOo0:Llyiahf/vczjk/db4;

.field public static final synthetic OooOOoo:[Llyiahf/vczjk/db4;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    new-instance v0, Llyiahf/vczjk/db4;

    const-string v1, "INT"

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/db4;->OooOOO0:Llyiahf/vczjk/db4;

    new-instance v1, Llyiahf/vczjk/db4;

    const-string v2, "LONG"

    const/4 v3, 0x1

    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v1, Llyiahf/vczjk/db4;->OooOOO:Llyiahf/vczjk/db4;

    new-instance v2, Llyiahf/vczjk/db4;

    const-string v3, "BIG_INTEGER"

    const/4 v4, 0x2

    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v2, Llyiahf/vczjk/db4;->OooOOOO:Llyiahf/vczjk/db4;

    new-instance v3, Llyiahf/vczjk/db4;

    const-string v4, "FLOAT"

    const/4 v5, 0x3

    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v3, Llyiahf/vczjk/db4;->OooOOOo:Llyiahf/vczjk/db4;

    new-instance v4, Llyiahf/vczjk/db4;

    const-string v5, "DOUBLE"

    const/4 v6, 0x4

    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v4, Llyiahf/vczjk/db4;->OooOOo0:Llyiahf/vczjk/db4;

    new-instance v5, Llyiahf/vczjk/db4;

    const-string v6, "BIG_DECIMAL"

    const/4 v7, 0x5

    invoke-direct {v5, v6, v7}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v5, Llyiahf/vczjk/db4;->OooOOo:Llyiahf/vczjk/db4;

    filled-new-array/range {v0 .. v5}, [Llyiahf/vczjk/db4;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/db4;->OooOOoo:[Llyiahf/vczjk/db4;

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/db4;
    .locals 1

    const-class v0, Llyiahf/vczjk/db4;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/db4;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/db4;
    .locals 1

    sget-object v0, Llyiahf/vczjk/db4;->OooOOoo:[Llyiahf/vczjk/db4;

    invoke-virtual {v0}, [Llyiahf/vczjk/db4;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/db4;

    return-object v0
.end method
