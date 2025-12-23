.class public final Llyiahf/vczjk/yy9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $coroutineScope:Llyiahf/vczjk/xr1;

.field final synthetic this$0:Llyiahf/vczjk/bz9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bz9;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/bz9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/yy9;->$coroutineScope:Llyiahf/vczjk/xr1;

    iput-object p2, p0, Llyiahf/vczjk/yy9;->this$0:Llyiahf/vczjk/bz9;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/qc2;

    iget-object p1, p0, Llyiahf/vczjk/yy9;->$coroutineScope:Llyiahf/vczjk/xr1;

    sget-object v0, Llyiahf/vczjk/as1;->OooOOOo:Llyiahf/vczjk/as1;

    new-instance v1, Llyiahf/vczjk/xy9;

    iget-object v2, p0, Llyiahf/vczjk/yy9;->this$0:Llyiahf/vczjk/bz9;

    const/4 v3, 0x0

    invoke-direct {v1, v2, v3}, Llyiahf/vczjk/xy9;-><init>(Llyiahf/vczjk/bz9;Llyiahf/vczjk/yo1;)V

    const/4 v2, 0x1

    invoke-static {p1, v3, v0, v1, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    new-instance p1, Llyiahf/vczjk/ef;

    const/4 v0, 0x3

    invoke-direct {p1, v0}, Llyiahf/vczjk/ef;-><init>(I)V

    return-object p1
.end method
