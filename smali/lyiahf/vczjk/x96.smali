.class public final Llyiahf/vczjk/x96;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO00o:Z

.field public final OooO0O0:Llyiahf/vczjk/jj0;

.field public final OooO0OO:Llyiahf/vczjk/r09;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xr1;ZLlyiahf/vczjk/ze3;Llyiahf/vczjk/d17;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p2, p0, Llyiahf/vczjk/x96;->OooO00o:Z

    sget-object p2, Llyiahf/vczjk/aj0;->OooOOO0:Llyiahf/vczjk/aj0;

    const/4 v0, -0x2

    const/4 v1, 0x4

    invoke-static {v0, v1, p2}, Llyiahf/vczjk/tg0;->OooO0o0(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jj0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/x96;->OooO0O0:Llyiahf/vczjk/jj0;

    new-instance p2, Llyiahf/vczjk/w96;

    const/4 v0, 0x0

    invoke-direct {p2, p4, p3, p0, v0}, Llyiahf/vczjk/w96;-><init>(Llyiahf/vczjk/y96;Llyiahf/vczjk/ze3;Llyiahf/vczjk/x96;Llyiahf/vczjk/yo1;)V

    const/4 p3, 0x3

    invoke-static {p1, v0, v0, p2, p3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/x96;->OooO0OO:Llyiahf/vczjk/r09;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/x96;->OooO0O0:Llyiahf/vczjk/jj0;

    new-instance v1, Ljava/util/concurrent/CancellationException;

    const-string v2, "onBack cancelled"

    invoke-direct {v1, v2}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    const/4 v2, 0x1

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/jj0;->OooOOO0(Ljava/lang/Throwable;Z)Z

    const/4 v0, 0x0

    iget-object v1, p0, Llyiahf/vczjk/x96;->OooO0OO:Llyiahf/vczjk/r09;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/k84;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    return-void
.end method
