.class public final Llyiahf/vczjk/ht1;
.super Llyiahf/vczjk/rt1;
.source "SourceFile"


# static fields
.field public static final OooOOO:Llyiahf/vczjk/ht1;

.field public static final OooOOOO:Llyiahf/vczjk/ht1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/ht1;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/rt1;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/ht1;->OooOOO:Llyiahf/vczjk/ht1;

    new-instance v0, Llyiahf/vczjk/ht1;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/rt1;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/ht1;->OooOOOO:Llyiahf/vczjk/ht1;

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/String;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/rt1;->OooOOO0:I

    if-eqz v0, :cond_0

    const-string v0, "true"

    return-object v0

    :cond_0
    const-string v0, "false"

    return-object v0
.end method

.method public final OooO0o0()Ljava/lang/String;
    .locals 1

    const-string v0, "boolean"

    return-object v0
.end method

.method public final getType()Llyiahf/vczjk/p1a;
    .locals 1

    sget-object v0, Llyiahf/vczjk/p1a;->OooOOo:Llyiahf/vczjk/p1a;

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/rt1;->OooOOO0:I

    if-eqz v0, :cond_0

    const-string v0, "boolean{true}"

    return-object v0

    :cond_0
    const-string v0, "boolean{false}"

    return-object v0
.end method
