.class public final Llyiahf/vczjk/fz1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/jz1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/jz1;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jz1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fz1;->this$0:Llyiahf/vczjk/jz1;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Ljava/lang/Throwable;

    if-eqz p1, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/fz1;->this$0:Llyiahf/vczjk/jz1;

    iget-object v0, v0, Llyiahf/vczjk/jz1;->OooO0oo:Llyiahf/vczjk/oO0OOo0o;

    new-instance v1, Llyiahf/vczjk/f13;

    invoke-direct {v1, p1}, Llyiahf/vczjk/f13;-><init>(Ljava/lang/Throwable;)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/oO0OOo0o;->Oooo0o(Llyiahf/vczjk/n29;)V

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/fz1;->this$0:Llyiahf/vczjk/jz1;

    iget-object p1, p1, Llyiahf/vczjk/jz1;->OooOO0:Llyiahf/vczjk/sc9;

    invoke-virtual {p1}, Llyiahf/vczjk/sc9;->OooO00o()Z

    move-result p1

    if-eqz p1, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/fz1;->this$0:Llyiahf/vczjk/jz1;

    iget-object p1, p1, Llyiahf/vczjk/jz1;->OooOO0:Llyiahf/vczjk/sc9;

    invoke-virtual {p1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/p96;

    invoke-virtual {p1}, Llyiahf/vczjk/p96;->close()V

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
