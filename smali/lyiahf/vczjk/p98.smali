.class public final Llyiahf/vczjk/p98;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/t98;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/t98;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/p98;->this$0:Llyiahf/vczjk/t98;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/p98;->this$0:Llyiahf/vczjk/t98;

    iget-object v0, v0, Llyiahf/vczjk/t98;->OooOoOO:Llyiahf/vczjk/z98;

    invoke-virtual {v0}, Llyiahf/vczjk/z98;->OooO0o()I

    move-result v0

    int-to-float v0, v0

    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    return-object v0
.end method
