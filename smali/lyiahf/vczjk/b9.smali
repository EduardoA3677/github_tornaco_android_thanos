.class public final Llyiahf/vczjk/b9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $targetValue:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Object;"
        }
    .end annotation
.end field

.field final synthetic this$0:Llyiahf/vczjk/d9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/d9;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/d9;Ljava/lang/Object;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/b9;->this$0:Llyiahf/vczjk/d9;

    iput-object p2, p0, Llyiahf/vczjk/b9;->$targetValue:Ljava/lang/Object;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/b9;->this$0:Llyiahf/vczjk/d9;

    iget-object v1, v0, Llyiahf/vczjk/d9;->OooOOO:Llyiahf/vczjk/s8;

    iget-object v2, p0, Llyiahf/vczjk/b9;->$targetValue:Ljava/lang/Object;

    invoke-virtual {v0}, Llyiahf/vczjk/d9;->OooO0Oo()Llyiahf/vczjk/lb5;

    move-result-object v3

    invoke-virtual {v3, v2}, Llyiahf/vczjk/lb5;->OooO0OO(Ljava/lang/Object;)F

    move-result v3

    invoke-static {v3}, Ljava/lang/Float;->isNaN(F)Z

    move-result v4

    if-nez v4, :cond_0

    iget-object v1, v1, Llyiahf/vczjk/s8;->OooO00o:Llyiahf/vczjk/d9;

    iget-object v4, v1, Llyiahf/vczjk/d9;->OooOO0:Llyiahf/vczjk/lr5;

    check-cast v4, Llyiahf/vczjk/zv8;

    invoke-virtual {v4, v3}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    iget-object v1, v1, Llyiahf/vczjk/d9;->OooOO0O:Llyiahf/vczjk/lr5;

    check-cast v1, Llyiahf/vczjk/zv8;

    const/4 v3, 0x0

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Llyiahf/vczjk/d9;->OooO0oo(Ljava/lang/Object;)V

    :cond_0
    invoke-virtual {v0, v2}, Llyiahf/vczjk/d9;->OooO0oO(Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
