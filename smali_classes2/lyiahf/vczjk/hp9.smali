.class public final Llyiahf/vczjk/hp9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOO0:Llyiahf/vczjk/hb8;

.field public final synthetic OooOOOO:Llyiahf/vczjk/bf3;

.field public final synthetic OooOOOo:Llyiahf/vczjk/a91;

.field public final synthetic OooOOo:Llyiahf/vczjk/jx9;

.field public final synthetic OooOOo0:Llyiahf/vczjk/le3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hb8;Llyiahf/vczjk/a91;Llyiahf/vczjk/bf3;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/jx9;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/hp9;->OooOOO0:Llyiahf/vczjk/hb8;

    iput-object p2, p0, Llyiahf/vczjk/hp9;->OooOOO:Llyiahf/vczjk/a91;

    iput-object p3, p0, Llyiahf/vczjk/hp9;->OooOOOO:Llyiahf/vczjk/bf3;

    iput-object p4, p0, Llyiahf/vczjk/hp9;->OooOOOo:Llyiahf/vczjk/a91;

    iput-object p5, p0, Llyiahf/vczjk/hp9;->OooOOo0:Llyiahf/vczjk/le3;

    iput-object p6, p0, Llyiahf/vczjk/hp9;->OooOOo:Llyiahf/vczjk/jx9;

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    check-cast p1, Llyiahf/vczjk/kj;

    check-cast p2, Ljava/lang/Boolean;

    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p2

    check-cast p3, Llyiahf/vczjk/rf1;

    check-cast p4, Ljava/lang/Number;

    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    const-string p4, "$this$AnimatedContent"

    invoke-static {p1, p4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p1, 0x0

    if-eqz p2, :cond_0

    check-cast p3, Llyiahf/vczjk/zf1;

    const p2, -0x787ccb17

    invoke-virtual {p3, p2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p2, p0, Llyiahf/vczjk/hp9;->OooOOO0:Llyiahf/vczjk/hb8;

    invoke-static {p2, p3, p1}, Llyiahf/vczjk/xr6;->OooO00o(Llyiahf/vczjk/hb8;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {p3, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_0

    :cond_0
    move-object v5, p3

    check-cast v5, Llyiahf/vczjk/zf1;

    const p2, -0x787bdb34

    invoke-virtual {v5, p2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v0, p0, Llyiahf/vczjk/hp9;->OooOOO:Llyiahf/vczjk/a91;

    iget-object v3, p0, Llyiahf/vczjk/hp9;->OooOOo0:Llyiahf/vczjk/le3;

    iget-object v4, p0, Llyiahf/vczjk/hp9;->OooOOo:Llyiahf/vczjk/jx9;

    iget-object v1, p0, Llyiahf/vczjk/hp9;->OooOOOO:Llyiahf/vczjk/bf3;

    iget-object v2, p0, Llyiahf/vczjk/hp9;->OooOOOo:Llyiahf/vczjk/a91;

    const/4 v6, 0x0

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/xr6;->OooO0o0(Llyiahf/vczjk/a91;Llyiahf/vczjk/bf3;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/jx9;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v5, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
