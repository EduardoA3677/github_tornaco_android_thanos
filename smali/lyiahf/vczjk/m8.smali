.class public final Llyiahf/vczjk/m8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/d9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/d9;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/d9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/m8;->this$0:Llyiahf/vczjk/d9;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/m8;->this$0:Llyiahf/vczjk/d9;

    invoke-virtual {v0}, Llyiahf/vczjk/d9;->OooO0Oo()Llyiahf/vczjk/lb5;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/m8;->this$0:Llyiahf/vczjk/d9;

    iget-object v1, v1, Llyiahf/vczjk/d9;->OooO0oo:Llyiahf/vczjk/w62;

    invoke-virtual {v1}, Llyiahf/vczjk/w62;->getValue()Ljava/lang/Object;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/xn6;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    return-object v2
.end method
