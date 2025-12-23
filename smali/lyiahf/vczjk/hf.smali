.class public final Llyiahf/vczjk/hf;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $popupLayout:Llyiahf/vczjk/zz6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zz6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/hf;->$popupLayout:Llyiahf/vczjk/zz6;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/xn4;

    invoke-interface {p1}, Llyiahf/vczjk/xn4;->OooOooO()Llyiahf/vczjk/xn4;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/hf;->$popupLayout:Llyiahf/vczjk/zz6;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zz6;->OooOOO0(Llyiahf/vczjk/xn4;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
