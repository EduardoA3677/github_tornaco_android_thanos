.class public final Llyiahf/vczjk/yq5;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/xm6;

.field public final OooO0O0:Llyiahf/vczjk/jn0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/xm6;)V
    .locals 1

    const-string v0, "scope"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "parent"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/yq5;->OooO00o:Llyiahf/vczjk/xm6;

    new-instance v0, Llyiahf/vczjk/jn0;

    iget-object p2, p2, Llyiahf/vczjk/xm6;->OooO00o:Llyiahf/vczjk/f43;

    invoke-direct {v0, p2, p1}, Llyiahf/vczjk/jn0;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/xr1;)V

    iput-object v0, p0, Llyiahf/vczjk/yq5;->OooO0O0:Llyiahf/vczjk/jn0;

    return-void
.end method
