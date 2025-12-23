.class public final Llyiahf/vczjk/lga;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/nga;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/nga;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nga;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/lga;->this$0:Llyiahf/vczjk/nga;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/lga;->this$0:Llyiahf/vczjk/nga;

    iget-object v1, v0, Llyiahf/vczjk/nga;->Oooo0o0:Landroid/view/View;

    invoke-virtual {v0}, Llyiahf/vczjk/nga;->getResetBlock()Llyiahf/vczjk/oe3;

    move-result-object v0

    invoke-interface {v0, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
