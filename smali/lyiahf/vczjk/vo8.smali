.class public final Llyiahf/vczjk/vo8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/uo8;
.implements Llyiahf/vczjk/xr1;
.implements Llyiahf/vczjk/if8;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/xr1;

.field public final OooOOO0:Llyiahf/vczjk/if8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/if8;)V
    .locals 1

    const-string v0, "scope"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "channel"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/vo8;->OooOOO0:Llyiahf/vczjk/if8;

    iput-object p1, p0, Llyiahf/vczjk/vo8;->OooOOO:Llyiahf/vczjk/xr1;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Throwable;)Z
    .locals 1

    const/4 p1, 0x0

    iget-object v0, p0, Llyiahf/vczjk/vo8;->OooOOO0:Llyiahf/vczjk/if8;

    invoke-interface {v0, p1}, Llyiahf/vczjk/if8;->OooO0o(Ljava/lang/Throwable;)Z

    move-result p1

    return p1
.end method

.method public final OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vo8;->OooOOO0:Llyiahf/vczjk/if8;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/if8;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vo8;->OooOOO0:Llyiahf/vczjk/if8;

    invoke-interface {v0, p1}, Llyiahf/vczjk/if8;->OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OoooOO0()Llyiahf/vczjk/or1;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vo8;->OooOOO:Llyiahf/vczjk/xr1;

    invoke-interface {v0}, Llyiahf/vczjk/xr1;->OoooOO0()Llyiahf/vczjk/or1;

    move-result-object v0

    return-object v0
.end method
