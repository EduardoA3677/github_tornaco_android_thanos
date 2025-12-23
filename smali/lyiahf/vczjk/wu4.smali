.class public final Llyiahf/vczjk/wu4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/zu4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zu4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/wu4;->this$0:Llyiahf/vczjk/zu4;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wu4;->this$0:Llyiahf/vczjk/zu4;

    iget-object v0, v0, Llyiahf/vczjk/zu4;->OooOoo0:Llyiahf/vczjk/ru4;

    invoke-interface {v0}, Llyiahf/vczjk/ru4;->OooO0Oo()F

    move-result v0

    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    return-object v0
.end method
