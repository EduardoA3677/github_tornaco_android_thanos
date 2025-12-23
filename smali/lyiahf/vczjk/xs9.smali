.class public abstract enum Llyiahf/vczjk/xs9;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/us9;

.field public static final enum OooOOO0:Llyiahf/vczjk/ts9;

.field public static final synthetic OooOOOO:[Llyiahf/vczjk/xs9;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Llyiahf/vczjk/ts9;

    invoke-direct {v0}, Llyiahf/vczjk/ts9;-><init>()V

    sput-object v0, Llyiahf/vczjk/xs9;->OooOOO0:Llyiahf/vczjk/ts9;

    new-instance v1, Llyiahf/vczjk/us9;

    invoke-direct {v1}, Llyiahf/vczjk/us9;-><init>()V

    sput-object v1, Llyiahf/vczjk/xs9;->OooOOO:Llyiahf/vczjk/us9;

    new-instance v2, Llyiahf/vczjk/vs9;

    invoke-direct {v2}, Llyiahf/vczjk/vs9;-><init>()V

    new-instance v3, Llyiahf/vczjk/ws9;

    invoke-direct {v3}, Llyiahf/vczjk/ws9;-><init>()V

    const/4 v4, 0x4

    new-array v4, v4, [Llyiahf/vczjk/xs9;

    const/4 v5, 0x0

    aput-object v0, v4, v5

    const/4 v0, 0x1

    aput-object v1, v4, v0

    const/4 v0, 0x2

    aput-object v2, v4, v0

    const/4 v0, 0x3

    aput-object v3, v4, v0

    sput-object v4, Llyiahf/vczjk/xs9;->OooOOOO:[Llyiahf/vczjk/xs9;

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/xs9;
    .locals 1

    const-class v0, Llyiahf/vczjk/xs9;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/xs9;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/xs9;
    .locals 1

    sget-object v0, Llyiahf/vczjk/xs9;->OooOOOO:[Llyiahf/vczjk/xs9;

    invoke-virtual {v0}, [Llyiahf/vczjk/xs9;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/xs9;

    return-object v0
.end method


# virtual methods
.method public abstract OooO00o(Llyiahf/vczjk/qb4;)Ljava/lang/Number;
.end method
