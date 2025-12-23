.class public final Llyiahf/vczjk/hi2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/li2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/li2;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/hi2;->this$0:Llyiahf/vczjk/li2;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    iget-object p1, p0, Llyiahf/vczjk/hi2;->this$0:Llyiahf/vczjk/li2;

    invoke-static {p1}, Llyiahf/vczjk/li2;->OooO00o(Llyiahf/vczjk/li2;)Llyiahf/vczjk/f62;

    move-result-object p1

    sget v0, Llyiahf/vczjk/xh2;->OooO0O0:F

    invoke-interface {p1, v0}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result p1

    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p1

    return-object p1
.end method
