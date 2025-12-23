.class public final Llyiahf/vczjk/gy1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


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

    iput-object p1, p0, Llyiahf/vczjk/gy1;->this$0:Llyiahf/vczjk/jz1;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gy1;->this$0:Llyiahf/vczjk/jz1;

    iget-object v0, v0, Llyiahf/vczjk/jz1;->OooOO0:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/p96;

    iget-object v0, v0, Llyiahf/vczjk/p96;->OooO0Oo:Llyiahf/vczjk/yp8;

    return-object v0
.end method
