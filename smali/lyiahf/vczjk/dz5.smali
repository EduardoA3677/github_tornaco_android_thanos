.class public final Llyiahf/vczjk/dz5;
.super Llyiahf/vczjk/zo1;
.source "SourceFile"


# instance fields
.field label:I

.field synthetic result:Ljava/lang/Object;

.field final synthetic this$0:Llyiahf/vczjk/fz5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fz5;Llyiahf/vczjk/zo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/dz5;->this$0:Llyiahf/vczjk/fz5;

    invoke-direct {p0, p2}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    iput-object p1, p0, Llyiahf/vczjk/dz5;->result:Ljava/lang/Object;

    iget p1, p0, Llyiahf/vczjk/dz5;->label:I

    const/high16 v0, -0x80000000

    or-int/2addr p1, v0

    iput p1, p0, Llyiahf/vczjk/dz5;->label:I

    iget-object v0, p0, Llyiahf/vczjk/dz5;->this$0:Llyiahf/vczjk/fz5;

    const-wide/16 v1, 0x0

    const-wide/16 v3, 0x0

    move-object v5, p0

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/fz5;->OooO00o(JJLlyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
