.class public final Llyiahf/vczjk/pf6;
.super Llyiahf/vczjk/qqa;
.source "SourceFile"


# instance fields
.field public final OooO:Llyiahf/vczjk/wj7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wj7;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/pf6;->OooO:Llyiahf/vczjk/wj7;

    return-void
.end method


# virtual methods
.method public final OooOooO()Llyiahf/vczjk/wj7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/pf6;->OooO:Llyiahf/vczjk/wj7;

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    const/4 v0, 0x1

    if-ne p0, p1, :cond_0

    return v0

    :cond_0
    instance-of v1, p1, Llyiahf/vczjk/pf6;

    const/4 v2, 0x0

    if-nez v1, :cond_1

    return v2

    :cond_1
    check-cast p1, Llyiahf/vczjk/pf6;

    iget-object p1, p1, Llyiahf/vczjk/pf6;->OooO:Llyiahf/vczjk/wj7;

    iget-object v1, p0, Llyiahf/vczjk/pf6;->OooO:Llyiahf/vczjk/wj7;

    invoke-static {v1, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_2

    return v2

    :cond_2
    return v0
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/pf6;->OooO:Llyiahf/vczjk/wj7;

    invoke-virtual {v0}, Llyiahf/vczjk/wj7;->hashCode()I

    move-result v0

    return v0
.end method
