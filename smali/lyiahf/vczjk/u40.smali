.class public final Llyiahf/vczjk/u40;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $this_getOutline:Llyiahf/vczjk/mm1;

.field final synthetic this$0:Llyiahf/vczjk/v40;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v40;Llyiahf/vczjk/to4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/u40;->this$0:Llyiahf/vczjk/v40;

    iput-object p2, p0, Llyiahf/vczjk/u40;->$this_getOutline:Llyiahf/vczjk/mm1;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/u40;->this$0:Llyiahf/vczjk/v40;

    iget-object v1, v0, Llyiahf/vczjk/v40;->OooOoo0:Llyiahf/vczjk/qj8;

    iget-object v2, p0, Llyiahf/vczjk/u40;->$this_getOutline:Llyiahf/vczjk/mm1;

    check-cast v2, Llyiahf/vczjk/to4;

    iget-object v2, v2, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    invoke-interface {v2}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v2

    iget-object v4, p0, Llyiahf/vczjk/u40;->$this_getOutline:Llyiahf/vczjk/mm1;

    check-cast v4, Llyiahf/vczjk/to4;

    invoke-virtual {v4}, Llyiahf/vczjk/to4;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v4

    iget-object v5, p0, Llyiahf/vczjk/u40;->$this_getOutline:Llyiahf/vczjk/mm1;

    invoke-interface {v1, v2, v3, v4, v5}, Llyiahf/vczjk/qj8;->OooooOo(JLlyiahf/vczjk/yn4;Llyiahf/vczjk/f62;)Llyiahf/vczjk/qqa;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/v40;->Oooo00O:Llyiahf/vczjk/qqa;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
