.class public final Llyiahf/vczjk/ii2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/li2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/li2;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ii2;->this$0:Llyiahf/vczjk/li2;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ii2;->this$0:Llyiahf/vczjk/li2;

    invoke-static {v0}, Llyiahf/vczjk/li2;->OooO00o(Llyiahf/vczjk/li2;)Llyiahf/vczjk/f62;

    move-result-object v0

    sget v1, Llyiahf/vczjk/xh2;->OooO0OO:F

    invoke-interface {v0, v1}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v0

    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    return-object v0
.end method
