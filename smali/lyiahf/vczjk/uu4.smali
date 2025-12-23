.class public final Llyiahf/vczjk/uu4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/zu4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zu4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/uu4;->this$0:Llyiahf/vczjk/zu4;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/uu4;->this$0:Llyiahf/vczjk/zu4;

    iget-object v0, v0, Llyiahf/vczjk/zu4;->OooOoOO:Llyiahf/vczjk/hh4;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/nt4;

    invoke-interface {v0}, Llyiahf/vczjk/nt4;->OooO00o()I

    move-result v1

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_1

    invoke-interface {v0, v2}, Llyiahf/vczjk/nt4;->OooO0O0(I)Ljava/lang/Object;

    move-result-object v3

    invoke-virtual {v3, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_0

    goto :goto_1

    :cond_0
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    const/4 v2, -0x1

    :goto_1
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1
.end method
