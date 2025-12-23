.class public final Llyiahf/vczjk/rm3;
.super Llyiahf/vczjk/gx3;
.source "SourceFile"


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/t92;)V
    .locals 0

    return-void
.end method

.method public final OooO0O0()Llyiahf/vczjk/i54;
    .locals 1

    sget-object v0, Llyiahf/vczjk/i54;->OooOOO0:Llyiahf/vczjk/i54;

    return-object v0
.end method

.method public final OooO0OO()I
    .locals 1

    const/16 v0, 0x70

    return v0
.end method

.method public final OooO0Oo(Llyiahf/vczjk/t92;Llyiahf/vczjk/ol0;)V
    .locals 12

    iget-object v0, p1, Llyiahf/vczjk/t92;->OooO0OO:Llyiahf/vczjk/rj5;

    invoke-virtual {v0}, Llyiahf/vczjk/bc8;->OooO0O0()I

    move-result v0

    iget-object v1, p1, Llyiahf/vczjk/t92;->OooO00o:Llyiahf/vczjk/rj5;

    invoke-virtual {v1}, Llyiahf/vczjk/bc8;->OooO0O0()I

    move-result v1

    iget-object v2, p1, Llyiahf/vczjk/t92;->OooO0OO:Llyiahf/vczjk/rj5;

    invoke-virtual {v2}, Llyiahf/vczjk/bc8;->OooO0O0()I

    move-result v3

    invoke-virtual {v2}, Llyiahf/vczjk/bc8;->OooO0o()V

    iget v2, v2, Llyiahf/vczjk/rj5;->OooO:I

    add-int/2addr v3, v2

    sub-int/2addr v3, v1

    const-string v2, "dex\n"

    const-string v4, "035"

    const-string v5, "\u0000"

    invoke-static {v2, v4, v5}, Llyiahf/vczjk/u81;->OooOOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p2}, Llyiahf/vczjk/ol0;->OooO0Oo()Z

    move-result v4

    const-string v5, "file size not yet known"

    const v6, 0x12345678

    const/16 v7, 0x70

    const/16 v8, 0x8

    const/4 v9, 0x4

    if-eqz v4, :cond_1

    new-instance v4, Llyiahf/vczjk/zt1;

    invoke-direct {v4, v2}, Llyiahf/vczjk/zt1;-><init>(Ljava/lang/String;)V

    invoke-virtual {v4}, Llyiahf/vczjk/zt1;->OooO0o()Ljava/lang/String;

    move-result-object v4

    new-instance v10, Ljava/lang/StringBuilder;

    const-string v11, "magic: "

    invoke-direct {v10, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v10, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {p2, v8, v4}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    const-string v4, "checksum"

    invoke-virtual {p2, v9, v4}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    const/16 v4, 0x14

    const-string v10, "signature"

    invoke-virtual {p2, v4, v10}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    iget v4, p1, Llyiahf/vczjk/t92;->OooOOOO:I

    if-ltz v4, :cond_0

    invoke-static {v4}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v4

    const-string v10, "file_size:       "

    invoke-virtual {v10, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    invoke-virtual {p2, v9, v4}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v7}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v4

    const-string v10, "header_size:     "

    invoke-virtual {v10, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    invoke-virtual {p2, v9, v4}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v6}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v4

    const-string v10, "endian_tag:      "

    invoke-virtual {v10, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    invoke-virtual {p2, v9, v4}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    const-string v4, "link_size:       0"

    invoke-virtual {p2, v9, v4}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    const-string v4, "link_off:        0"

    invoke-virtual {p2, v9, v4}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v4

    const-string v10, "map_off:         "

    invoke-virtual {v10, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    invoke-virtual {p2, v9, v4}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/RuntimeException;

    invoke-direct {p1, v5}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    :goto_0
    const/4 v4, 0x0

    move v10, v4

    :goto_1
    if-ge v10, v8, :cond_2

    invoke-virtual {v2, v10}, Ljava/lang/String;->charAt(I)C

    move-result v11

    invoke-virtual {p2, v11}, Llyiahf/vczjk/ol0;->OooO(I)V

    add-int/lit8 v10, v10, 0x1

    goto :goto_1

    :cond_2
    const/16 v2, 0x18

    invoke-virtual {p2, v2}, Llyiahf/vczjk/ol0;->OooOOO(I)V

    iget v2, p1, Llyiahf/vczjk/t92;->OooOOOO:I

    if-ltz v2, :cond_12

    invoke-virtual {p2, v2}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    invoke-virtual {p2, v7}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    invoke-virtual {p2, v6}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    invoke-virtual {p2, v8}, Llyiahf/vczjk/ol0;->OooOOO(I)V

    invoke-virtual {p2, v0}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    iget-object v0, p1, Llyiahf/vczjk/t92;->OooO0o0:Llyiahf/vczjk/ce7;

    invoke-virtual {v0}, Llyiahf/vczjk/bc8;->OooO0o()V

    iget-object v2, v0, Llyiahf/vczjk/ce7;->OooO0oO:Ljava/lang/Object;

    check-cast v2, Ljava/util/TreeMap;

    invoke-virtual {v2}, Ljava/util/TreeMap;->size()I

    move-result v2

    if-nez v2, :cond_3

    move v0, v4

    goto :goto_2

    :cond_3
    invoke-virtual {v0}, Llyiahf/vczjk/bc8;->OooO0O0()I

    move-result v0

    :goto_2
    invoke-virtual {p2}, Llyiahf/vczjk/ol0;->OooO0Oo()Z

    move-result v5

    if-eqz v5, :cond_4

    invoke-static {v2}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v5

    const-string v6, "string_ids_size: "

    invoke-virtual {v6, v5}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {p2, v9, v5}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v5

    const-string v6, "string_ids_off:  "

    invoke-virtual {v6, v5}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {p2, v9, v5}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    :cond_4
    invoke-virtual {p2, v2}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    invoke-virtual {p2, v0}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    iget-object v0, p1, Llyiahf/vczjk/t92;->OooO0o:Llyiahf/vczjk/ce7;

    invoke-virtual {v0}, Llyiahf/vczjk/bc8;->OooO0o()V

    iget-object v2, v0, Llyiahf/vczjk/ce7;->OooO0oO:Ljava/lang/Object;

    check-cast v2, Ljava/util/TreeMap;

    invoke-virtual {v2}, Ljava/util/TreeMap;->size()I

    move-result v5

    if-nez v5, :cond_5

    move v0, v4

    goto :goto_3

    :cond_5
    invoke-virtual {v0}, Llyiahf/vczjk/bc8;->OooO0O0()I

    move-result v0

    :goto_3
    const/high16 v6, 0x10000

    if-gt v5, v6, :cond_11

    invoke-virtual {p2}, Llyiahf/vczjk/ol0;->OooO0Oo()Z

    move-result v2

    if-eqz v2, :cond_6

    invoke-static {v5}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v2

    const-string v7, "type_ids_size:   "

    invoke-virtual {v7, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p2, v9, v2}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v2

    const-string v7, "type_ids_off:    "

    invoke-virtual {v7, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p2, v9, v2}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    :cond_6
    invoke-virtual {p2, v5}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    invoke-virtual {p2, v0}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    iget-object v0, p1, Llyiahf/vczjk/t92;->OooO0oO:Llyiahf/vczjk/ce7;

    invoke-virtual {v0}, Llyiahf/vczjk/bc8;->OooO0o()V

    iget-object v2, v0, Llyiahf/vczjk/ce7;->OooO0oO:Ljava/lang/Object;

    check-cast v2, Ljava/util/TreeMap;

    invoke-virtual {v2}, Ljava/util/TreeMap;->size()I

    move-result v2

    if-nez v2, :cond_7

    move v0, v4

    goto :goto_4

    :cond_7
    invoke-virtual {v0}, Llyiahf/vczjk/bc8;->OooO0O0()I

    move-result v0

    :goto_4
    if-gt v2, v6, :cond_10

    invoke-virtual {p2}, Llyiahf/vczjk/ol0;->OooO0Oo()Z

    move-result v5

    if-eqz v5, :cond_8

    invoke-static {v2}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v5

    const-string v6, "proto_ids_size:  "

    invoke-virtual {v6, v5}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {p2, v9, v5}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v5

    const-string v6, "proto_ids_off:   "

    invoke-virtual {v6, v5}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {p2, v9, v5}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    :cond_8
    invoke-virtual {p2, v2}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    invoke-virtual {p2, v0}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    iget-object v0, p1, Llyiahf/vczjk/t92;->OooO0oo:Llyiahf/vczjk/ix2;

    invoke-virtual {v0}, Llyiahf/vczjk/bc8;->OooO0o()V

    iget-object v2, v0, Llyiahf/vczjk/ix2;->OooO0o:Ljava/util/TreeMap;

    invoke-virtual {v2}, Ljava/util/TreeMap;->size()I

    move-result v2

    if-nez v2, :cond_9

    move v0, v4

    goto :goto_5

    :cond_9
    invoke-virtual {v0}, Llyiahf/vczjk/bc8;->OooO0O0()I

    move-result v0

    :goto_5
    invoke-virtual {p2}, Llyiahf/vczjk/ol0;->OooO0Oo()Z

    move-result v5

    if-eqz v5, :cond_a

    invoke-static {v2}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v5

    const-string v6, "field_ids_size:  "

    invoke-virtual {v6, v5}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {p2, v9, v5}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v5

    const-string v6, "field_ids_off:   "

    invoke-virtual {v6, v5}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {p2, v9, v5}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    :cond_a
    invoke-virtual {p2, v2}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    invoke-virtual {p2, v0}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    iget-object v0, p1, Llyiahf/vczjk/t92;->OooO:Llyiahf/vczjk/bj5;

    invoke-virtual {v0}, Llyiahf/vczjk/bc8;->OooO0o()V

    iget-object v2, v0, Llyiahf/vczjk/bj5;->OooO0o:Ljava/util/TreeMap;

    invoke-virtual {v2}, Ljava/util/TreeMap;->size()I

    move-result v2

    if-nez v2, :cond_b

    move v0, v4

    goto :goto_6

    :cond_b
    invoke-virtual {v0}, Llyiahf/vczjk/bc8;->OooO0O0()I

    move-result v0

    :goto_6
    invoke-virtual {p2}, Llyiahf/vczjk/ol0;->OooO0Oo()Z

    move-result v5

    if-eqz v5, :cond_c

    invoke-static {v2}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v5

    const-string v6, "method_ids_size: "

    invoke-virtual {v6, v5}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {p2, v9, v5}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v5

    const-string v6, "method_ids_off:  "

    invoke-virtual {v6, v5}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {p2, v9, v5}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    :cond_c
    invoke-virtual {p2, v2}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    invoke-virtual {p2, v0}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    iget-object p1, p1, Llyiahf/vczjk/t92;->OooOO0:Llyiahf/vczjk/ay0;

    invoke-virtual {p1}, Llyiahf/vczjk/bc8;->OooO0o()V

    iget-object v0, p1, Llyiahf/vczjk/ay0;->OooO0o:Ljava/util/TreeMap;

    invoke-virtual {v0}, Ljava/util/TreeMap;->size()I

    move-result v0

    if-nez v0, :cond_d

    goto :goto_7

    :cond_d
    invoke-virtual {p1}, Llyiahf/vczjk/bc8;->OooO0O0()I

    move-result v4

    :goto_7
    invoke-virtual {p2}, Llyiahf/vczjk/ol0;->OooO0Oo()Z

    move-result p1

    if-eqz p1, :cond_e

    invoke-static {v0}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object p1

    const-string v2, "class_defs_size: "

    invoke-virtual {v2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, v9, p1}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v4}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object p1

    const-string v2, "class_defs_off:  "

    invoke-virtual {v2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, v9, p1}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    :cond_e
    invoke-virtual {p2, v0}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    invoke-virtual {p2, v4}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    invoke-virtual {p2}, Llyiahf/vczjk/ol0;->OooO0Oo()Z

    move-result p1

    if-eqz p1, :cond_f

    invoke-static {v3}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object p1

    const-string v0, "data_size:       "

    invoke-virtual {v0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, v9, p1}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object p1

    const-string v0, "data_off:        "

    invoke-virtual {v0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, v9, p1}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    :cond_f
    invoke-virtual {p2, v3}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    invoke-virtual {p2, v1}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    return-void

    :cond_10
    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string p2, "too many proto ids"

    invoke-direct {p1, p2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_11
    new-instance p1, Llyiahf/vczjk/u92;

    invoke-virtual {v2}, Ljava/util/TreeMap;->values()Ljava/util/Collection;

    move-result-object p2

    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result p2

    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    filled-new-array {p2, v0}, [Ljava/lang/Object;

    move-result-object p2

    const-string v0, "Too many type identifiers to fit in one dex file: %1$d; max is %2$d.%nYou may try using multi-dex. If multi-dex is enabled then the list of classes for the boot dex list is too large."

    invoke-static {v0, p2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    const/4 v0, 0x0

    invoke-direct {p1, p2, v0}, Llyiahf/vczjk/vr2;-><init>(Ljava/lang/String;Ljava/lang/Exception;)V

    throw p1

    :cond_12
    new-instance p1, Ljava/lang/RuntimeException;

    invoke-direct {p1, v5}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
