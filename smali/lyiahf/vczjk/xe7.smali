.class public final Llyiahf/vczjk/xe7;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/bf7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bf7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/xe7;->this$0:Llyiahf/vczjk/bf7;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/xe7;->this$0:Llyiahf/vczjk/bf7;

    iget-object v0, v0, Llyiahf/vczjk/bf7;->OooO0o:Llyiahf/vczjk/lr5;

    check-cast v0, Llyiahf/vczjk/zv8;

    invoke-virtual {v0}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v0

    const/high16 v1, 0x3f000000    # 0.5f

    mul-float/2addr v0, v1

    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    return-object v0
.end method
