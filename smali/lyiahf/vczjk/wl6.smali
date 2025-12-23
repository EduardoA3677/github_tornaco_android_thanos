.class public final Llyiahf/vczjk/wl6;
.super Llyiahf/vczjk/zo1;
.source "SourceFile"


# instance fields
.field F$0:F

.field I$0:I

.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I

.field synthetic result:Ljava/lang/Object;

.field final synthetic this$0:Llyiahf/vczjk/lm6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lm6;Llyiahf/vczjk/zo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/wl6;->this$0:Llyiahf/vczjk/lm6;

    invoke-direct {p0, p2}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    iput-object p1, p0, Llyiahf/vczjk/wl6;->result:Ljava/lang/Object;

    iget p1, p0, Llyiahf/vczjk/wl6;->label:I

    const/high16 v0, -0x80000000

    or-int/2addr p1, v0

    iput p1, p0, Llyiahf/vczjk/wl6;->label:I

    iget-object p1, p0, Llyiahf/vczjk/wl6;->this$0:Llyiahf/vczjk/lm6;

    const/4 v0, 0x0

    const/4 v1, 0x0

    invoke-virtual {p1, v1, v0, p0}, Llyiahf/vczjk/lm6;->OooO0o(ILlyiahf/vczjk/wz8;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
