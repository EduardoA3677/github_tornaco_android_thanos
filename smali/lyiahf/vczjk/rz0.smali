.class public final Llyiahf/vczjk/rz0;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $enabled:Z

.field final synthetic $onClick:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $onClickLabel:Ljava/lang/String;

.field final synthetic $role:Llyiahf/vczjk/gu7;


# direct methods
.method public constructor <init>(ZLjava/lang/String;Llyiahf/vczjk/le3;)V
    .locals 0

    iput-boolean p1, p0, Llyiahf/vczjk/rz0;->$enabled:Z

    iput-object p2, p0, Llyiahf/vczjk/rz0;->$onClickLabel:Ljava/lang/String;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/rz0;->$role:Llyiahf/vczjk/gu7;

    iput-object p3, p0, Llyiahf/vczjk/rz0;->$onClick:Llyiahf/vczjk/le3;

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    check-cast p1, Llyiahf/vczjk/kl5;

    check-cast p2, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    check-cast p2, Llyiahf/vczjk/zf1;

    const p1, -0x2d10e1f7

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object p1, Landroidx/compose/foundation/OooO0o;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p1

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/lx3;

    instance-of p1, v2, Llyiahf/vczjk/px3;

    const/4 p3, 0x0

    if-eqz p1, :cond_0

    const p1, 0x24d0a640

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 p1, 0x0

    :goto_0
    move-object v1, p1

    goto :goto_1

    :cond_0
    const p1, 0x24d2ac4a

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne p1, v0, :cond_1

    invoke-static {p2}, Llyiahf/vczjk/ix8;->OooOOo0(Llyiahf/vczjk/zf1;)Llyiahf/vczjk/sr5;

    move-result-object p1

    :cond_1
    check-cast p1, Llyiahf/vczjk/rr5;

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_0

    :goto_1
    sget-object v0, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    iget-boolean v3, p0, Llyiahf/vczjk/rz0;->$enabled:Z

    iget-object v4, p0, Llyiahf/vczjk/rz0;->$onClickLabel:Ljava/lang/String;

    iget-object v5, p0, Llyiahf/vczjk/rz0;->$role:Llyiahf/vczjk/gu7;

    iget-object v6, p0, Llyiahf/vczjk/rz0;->$onClick:Llyiahf/vczjk/le3;

    invoke-static/range {v0 .. v6}, Landroidx/compose/foundation/OooO00o;->OooO0O0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/rr5;Llyiahf/vczjk/lx3;ZLjava/lang/String;Llyiahf/vczjk/gu7;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kl5;

    move-result-object p1

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object p1
.end method
