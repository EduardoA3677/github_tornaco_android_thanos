.class public final Llyiahf/vczjk/pa8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/ra8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ra8;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pa8;->this$0:Llyiahf/vczjk/ra8;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result p1

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->floatValue()F

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/pa8;->this$0:Llyiahf/vczjk/ra8;

    invoke-virtual {v0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/oa8;

    iget-object v2, p0, Llyiahf/vczjk/pa8;->this$0:Llyiahf/vczjk/ra8;

    const/4 v3, 0x0

    invoke-direct {v1, v2, p1, p2, v3}, Llyiahf/vczjk/oa8;-><init>(Llyiahf/vczjk/ra8;FFLlyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    invoke-static {v0, v3, v3, v1, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1
.end method
