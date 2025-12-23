.class public final Llyiahf/vczjk/p16;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $drawBlockCallToDrawModifiers:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic this$0:Llyiahf/vczjk/v16;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v16;Llyiahf/vczjk/q16;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/p16;->this$0:Llyiahf/vczjk/v16;

    iput-object p2, p0, Llyiahf/vczjk/p16;->$drawBlockCallToDrawModifiers:Llyiahf/vczjk/le3;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/eq0;

    check-cast p2, Llyiahf/vczjk/kj3;

    iget-object v0, p0, Llyiahf/vczjk/p16;->this$0:Llyiahf/vczjk/v16;

    iget-object v0, v0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->Oooo0()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/p16;->this$0:Llyiahf/vczjk/v16;

    iput-object p1, v0, Llyiahf/vczjk/v16;->Oooo0oo:Llyiahf/vczjk/eq0;

    iput-object p2, v0, Llyiahf/vczjk/v16;->Oooo0oO:Llyiahf/vczjk/kj3;

    iget-object p1, v0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    invoke-static {p1}, Llyiahf/vczjk/uo4;->OooO00o(Llyiahf/vczjk/ro4;)Llyiahf/vczjk/tg6;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/xa;

    invoke-virtual {p1}, Llyiahf/vczjk/xa;->getSnapshotObserver()Llyiahf/vczjk/vg6;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/p16;->this$0:Llyiahf/vczjk/v16;

    sget-object v0, Llyiahf/vczjk/v16;->OoooOO0:Llyiahf/vczjk/ft7;

    sget-object v0, Llyiahf/vczjk/k65;->OooOo00:Llyiahf/vczjk/k65;

    iget-object v1, p0, Llyiahf/vczjk/p16;->$drawBlockCallToDrawModifiers:Llyiahf/vczjk/le3;

    invoke-virtual {p1, p2, v0, v1}, Llyiahf/vczjk/vg6;->OooO00o(Llyiahf/vczjk/ug6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;)V

    iget-object p1, p0, Llyiahf/vczjk/p16;->this$0:Llyiahf/vczjk/v16;

    const/4 p2, 0x0

    iput-boolean p2, p1, Llyiahf/vczjk/v16;->OoooO0:Z

    goto :goto_0

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/p16;->this$0:Llyiahf/vczjk/v16;

    const/4 p2, 0x1

    iput-boolean p2, p1, Llyiahf/vczjk/v16;->OoooO0:Z

    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
