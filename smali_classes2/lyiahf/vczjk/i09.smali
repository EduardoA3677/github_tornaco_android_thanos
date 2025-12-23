.class public final Llyiahf/vczjk/i09;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/yo1;
.implements Llyiahf/vczjk/zr1;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/or1;

.field public final OooOOO0:Llyiahf/vczjk/yo1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/or1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/i09;->OooOOO0:Llyiahf/vczjk/yo1;

    iput-object p2, p0, Llyiahf/vczjk/i09;->OooOOO:Llyiahf/vczjk/or1;

    return-void
.end method


# virtual methods
.method public final getCallerFrame()Llyiahf/vczjk/zr1;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/i09;->OooOOO0:Llyiahf/vczjk/yo1;

    instance-of v1, v0, Llyiahf/vczjk/zr1;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/zr1;

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public final getContext()Llyiahf/vczjk/or1;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/i09;->OooOOO:Llyiahf/vczjk/or1;

    return-object v0
.end method

.method public final resumeWith(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/i09;->OooOOO0:Llyiahf/vczjk/yo1;

    invoke-interface {v0, p1}, Llyiahf/vczjk/yo1;->resumeWith(Ljava/lang/Object;)V

    return-void
.end method
