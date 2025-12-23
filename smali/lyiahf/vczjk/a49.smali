.class public final Llyiahf/vczjk/a49;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $block:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $this_loadStatusFuture:Landroidx/work/impl/WorkDatabase;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/z39;Landroidx/work/impl/WorkDatabase;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/a49;->$block:Llyiahf/vczjk/oe3;

    iput-object p2, p0, Llyiahf/vczjk/a49;->$this_loadStatusFuture:Landroidx/work/impl/WorkDatabase;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/a49;->$block:Llyiahf/vczjk/oe3;

    iget-object v1, p0, Llyiahf/vczjk/a49;->$this_loadStatusFuture:Landroidx/work/impl/WorkDatabase;

    invoke-interface {v0, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method
