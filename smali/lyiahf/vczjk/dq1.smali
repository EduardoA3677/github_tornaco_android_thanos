.class public final Llyiahf/vczjk/dq1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $bringIntoViewRequester:Llyiahf/vczjk/th0;

.field final synthetic $coroutineScope:Llyiahf/vczjk/xr1;

.field final synthetic $enabled:Z

.field final synthetic $imeOptions:Llyiahf/vczjk/wv3;

.field final synthetic $manager:Llyiahf/vczjk/mk9;

.field final synthetic $offsetMapping:Llyiahf/vczjk/s86;

.field final synthetic $readOnly:Z

.field final synthetic $state:Llyiahf/vczjk/lx4;

.field final synthetic $textInputService:Llyiahf/vczjk/tl9;

.field final synthetic $value:Llyiahf/vczjk/gl9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lx4;ZZLlyiahf/vczjk/tl9;Llyiahf/vczjk/gl9;Llyiahf/vczjk/wv3;Llyiahf/vczjk/s86;Llyiahf/vczjk/mk9;Llyiahf/vczjk/xr1;Llyiahf/vczjk/th0;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/dq1;->$state:Llyiahf/vczjk/lx4;

    iput-boolean p2, p0, Llyiahf/vczjk/dq1;->$enabled:Z

    iput-boolean p3, p0, Llyiahf/vczjk/dq1;->$readOnly:Z

    iput-object p4, p0, Llyiahf/vczjk/dq1;->$textInputService:Llyiahf/vczjk/tl9;

    iput-object p5, p0, Llyiahf/vczjk/dq1;->$value:Llyiahf/vczjk/gl9;

    iput-object p6, p0, Llyiahf/vczjk/dq1;->$imeOptions:Llyiahf/vczjk/wv3;

    iput-object p7, p0, Llyiahf/vczjk/dq1;->$offsetMapping:Llyiahf/vczjk/s86;

    iput-object p8, p0, Llyiahf/vczjk/dq1;->$manager:Llyiahf/vczjk/mk9;

    iput-object p9, p0, Llyiahf/vczjk/dq1;->$coroutineScope:Llyiahf/vczjk/xr1;

    iput-object p10, p0, Llyiahf/vczjk/dq1;->$bringIntoViewRequester:Llyiahf/vczjk/th0;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    check-cast p1, Llyiahf/vczjk/z83;

    iget-object v0, p0, Llyiahf/vczjk/dq1;->$state:Llyiahf/vczjk/lx4;

    invoke-virtual {v0}, Llyiahf/vczjk/lx4;->OooO0O0()Z

    move-result v0

    check-cast p1, Llyiahf/vczjk/a93;

    invoke-virtual {p1}, Llyiahf/vczjk/a93;->OooO00o()Z

    move-result v1

    if-ne v0, v1, :cond_0

    goto :goto_1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/dq1;->$state:Llyiahf/vczjk/lx4;

    invoke-virtual {p1}, Llyiahf/vczjk/a93;->OooO00o()Z

    move-result v1

    iget-object v0, v0, Llyiahf/vczjk/lx4;->OooO0o:Llyiahf/vczjk/qs5;

    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v1

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/dq1;->$state:Llyiahf/vczjk/lx4;

    invoke-virtual {v0}, Llyiahf/vczjk/lx4;->OooO0O0()Z

    move-result v0

    if-eqz v0, :cond_1

    iget-boolean v0, p0, Llyiahf/vczjk/dq1;->$enabled:Z

    if-eqz v0, :cond_1

    iget-boolean v0, p0, Llyiahf/vczjk/dq1;->$readOnly:Z

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/dq1;->$textInputService:Llyiahf/vczjk/tl9;

    iget-object v1, p0, Llyiahf/vczjk/dq1;->$state:Llyiahf/vczjk/lx4;

    iget-object v2, p0, Llyiahf/vczjk/dq1;->$value:Llyiahf/vczjk/gl9;

    iget-object v3, p0, Llyiahf/vczjk/dq1;->$imeOptions:Llyiahf/vczjk/wv3;

    iget-object v4, p0, Llyiahf/vczjk/dq1;->$offsetMapping:Llyiahf/vczjk/s86;

    invoke-static {v0, v1, v2, v3, v4}, Llyiahf/vczjk/sb;->OooOOo(Llyiahf/vczjk/tl9;Llyiahf/vczjk/lx4;Llyiahf/vczjk/gl9;Llyiahf/vczjk/wv3;Llyiahf/vczjk/s86;)V

    goto :goto_0

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/dq1;->$state:Llyiahf/vczjk/lx4;

    invoke-static {v0}, Llyiahf/vczjk/sb;->OooOOOo(Llyiahf/vczjk/lx4;)V

    :goto_0
    invoke-virtual {p1}, Llyiahf/vczjk/a93;->OooO00o()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/dq1;->$state:Llyiahf/vczjk/lx4;

    invoke-virtual {v0}, Llyiahf/vczjk/lx4;->OooO0Oo()Llyiahf/vczjk/nm9;

    move-result-object v6

    if-eqz v6, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/dq1;->$coroutineScope:Llyiahf/vczjk/xr1;

    iget-object v3, p0, Llyiahf/vczjk/dq1;->$bringIntoViewRequester:Llyiahf/vczjk/th0;

    iget-object v4, p0, Llyiahf/vczjk/dq1;->$value:Llyiahf/vczjk/gl9;

    iget-object v5, p0, Llyiahf/vczjk/dq1;->$state:Llyiahf/vczjk/lx4;

    iget-object v7, p0, Llyiahf/vczjk/dq1;->$offsetMapping:Llyiahf/vczjk/s86;

    new-instance v2, Llyiahf/vczjk/cq1;

    const/4 v8, 0x0

    invoke-direct/range {v2 .. v8}, Llyiahf/vczjk/cq1;-><init>(Llyiahf/vczjk/th0;Llyiahf/vczjk/gl9;Llyiahf/vczjk/lx4;Llyiahf/vczjk/nm9;Llyiahf/vczjk/s86;Llyiahf/vczjk/yo1;)V

    const/4 v3, 0x3

    invoke-static {v0, v1, v1, v2, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/a93;->OooO00o()Z

    move-result p1

    if-nez p1, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/dq1;->$manager:Llyiahf/vczjk/mk9;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/mk9;->OooO0oO(Llyiahf/vczjk/p86;)V

    :cond_3
    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
