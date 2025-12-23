.class public final Llyiahf/vczjk/ly4;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/ky4;

.field public final OooO0O0:Llyiahf/vczjk/jy4;

.field public final OooO0OO:Llyiahf/vczjk/ec2;

.field public final OooO0Oo:Llyiahf/vczjk/p61;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ky4;Llyiahf/vczjk/jy4;Llyiahf/vczjk/ec2;Llyiahf/vczjk/v74;)V
    .locals 1

    const-string v0, "lifecycle"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "minState"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "dispatchQueue"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ly4;->OooO00o:Llyiahf/vczjk/ky4;

    iput-object p2, p0, Llyiahf/vczjk/ly4;->OooO0O0:Llyiahf/vczjk/jy4;

    iput-object p3, p0, Llyiahf/vczjk/ly4;->OooO0OO:Llyiahf/vczjk/ec2;

    new-instance p2, Llyiahf/vczjk/p61;

    const/4 p3, 0x2

    invoke-direct {p2, p3, p0, p4}, Llyiahf/vczjk/p61;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iput-object p2, p0, Llyiahf/vczjk/ly4;->OooO0Oo:Llyiahf/vczjk/p61;

    invoke-virtual {p1}, Llyiahf/vczjk/ky4;->OooO0O0()Llyiahf/vczjk/jy4;

    move-result-object p3

    sget-object v0, Llyiahf/vczjk/jy4;->OooOOO0:Llyiahf/vczjk/jy4;

    if-ne p3, v0, :cond_0

    const/4 p1, 0x0

    invoke-interface {p4, p1}, Llyiahf/vczjk/v74;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    invoke-virtual {p0}, Llyiahf/vczjk/ly4;->OooO00o()V

    return-void

    :cond_0
    invoke-virtual {p1, p2}, Llyiahf/vczjk/ky4;->OooO00o(Llyiahf/vczjk/ty4;)V

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ly4;->OooO0Oo:Llyiahf/vczjk/p61;

    iget-object v1, p0, Llyiahf/vczjk/ly4;->OooO00o:Llyiahf/vczjk/ky4;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/ky4;->OooO0OO(Llyiahf/vczjk/ty4;)V

    iget-object v0, p0, Llyiahf/vczjk/ly4;->OooO0OO:Llyiahf/vczjk/ec2;

    const/4 v1, 0x1

    iput-boolean v1, v0, Llyiahf/vczjk/ec2;->OooOOO:Z

    invoke-virtual {v0}, Llyiahf/vczjk/ec2;->OooO00o()V

    return-void
.end method
