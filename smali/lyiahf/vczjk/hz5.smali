.class public final Llyiahf/vczjk/hz5;
.super Llyiahf/vczjk/zo1;
.source "SourceFile"


# instance fields
.field J$0:J

.field L$0:Ljava/lang/Object;

.field label:I

.field synthetic result:Ljava/lang/Object;

.field final synthetic this$0:Llyiahf/vczjk/jz5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jz5;Llyiahf/vczjk/zo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/hz5;->this$0:Llyiahf/vczjk/jz5;

    invoke-direct {p0, p2}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    iput-object p1, p0, Llyiahf/vczjk/hz5;->result:Ljava/lang/Object;

    iget p1, p0, Llyiahf/vczjk/hz5;->label:I

    const/high16 v0, -0x80000000

    or-int/2addr p1, v0

    iput p1, p0, Llyiahf/vczjk/hz5;->label:I

    iget-object p1, p0, Llyiahf/vczjk/hz5;->this$0:Llyiahf/vczjk/jz5;

    const-wide/16 v0, 0x0

    invoke-virtual {p1, v0, v1, p0}, Llyiahf/vczjk/jz5;->OoooOO0(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
