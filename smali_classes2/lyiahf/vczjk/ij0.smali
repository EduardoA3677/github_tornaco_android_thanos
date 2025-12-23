.class public final Llyiahf/vczjk/ij0;
.super Llyiahf/vczjk/zo1;
.source "SourceFile"


# instance fields
.field I$0:I

.field J$0:J

.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I

.field synthetic result:Ljava/lang/Object;

.field final synthetic this$0:Llyiahf/vczjk/jj0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/jj0;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jj0;Llyiahf/vczjk/zo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ij0;->this$0:Llyiahf/vczjk/jj0;

    invoke-direct {p0, p2}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    iput-object p1, p0, Llyiahf/vczjk/ij0;->result:Ljava/lang/Object;

    iget p1, p0, Llyiahf/vczjk/ij0;->label:I

    const/high16 v0, -0x80000000

    or-int/2addr p1, v0

    iput p1, p0, Llyiahf/vczjk/ij0;->label:I

    iget-object v0, p0, Llyiahf/vczjk/ij0;->this$0:Llyiahf/vczjk/jj0;

    const/4 v2, 0x0

    const-wide/16 v3, 0x0

    const/4 v1, 0x0

    move-object v5, p0

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/jj0;->OooOooo(Llyiahf/vczjk/kt0;IJLlyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, v0, :cond_0

    return-object p1

    :cond_0
    new-instance v0, Llyiahf/vczjk/jt0;

    invoke-direct {v0, p1}, Llyiahf/vczjk/jt0;-><init>(Ljava/lang/Object;)V

    return-object v0
.end method
