.class public final synthetic Llyiahf/vczjk/ki9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/w21;
.implements Llyiahf/vczjk/kf3;


# instance fields
.field public final synthetic OooOOO0:Llyiahf/vczjk/n83;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/n83;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ki9;->OooOOO0:Llyiahf/vczjk/n83;

    return-void
.end method


# virtual methods
.method public final OooO00o()J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ki9;->OooOOO0:Llyiahf/vczjk/n83;

    invoke-interface {v0}, Llyiahf/vczjk/hh4;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/n21;

    iget-wide v0, v0, Llyiahf/vczjk/n21;->OooO00o:J

    return-wide v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/cf3;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ki9;->OooOOO0:Llyiahf/vczjk/n83;

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    instance-of v0, p1, Llyiahf/vczjk/w21;

    if-eqz v0, :cond_0

    instance-of v0, p1, Llyiahf/vczjk/kf3;

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/ki9;->OooOOO0:Llyiahf/vczjk/n83;

    check-cast p1, Llyiahf/vczjk/kf3;

    invoke-interface {p1}, Llyiahf/vczjk/kf3;->OooO0O0()Llyiahf/vczjk/cf3;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ab7;->equals(Ljava/lang/Object;)Z

    move-result p1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ki9;->OooOOO0:Llyiahf/vczjk/n83;

    invoke-virtual {v0}, Llyiahf/vczjk/ab7;->hashCode()I

    move-result v0

    return v0
.end method
